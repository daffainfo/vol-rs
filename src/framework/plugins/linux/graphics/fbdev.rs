//! List the framebuffer devices and their state.
//!
//! A framebuffer holds what is on screen. Recovering its parameters is the
//! first step towards reconstructing the display at the time of capture.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{ConfigValue, Configuration, Context, Module};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::objects::utility::pointer_to_string;
use crate::framework::objects::Object;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};

pub struct Fbdev;

impl Plugin for Fbdev {
    fn name(&self) -> &'static str {
        "linux.graphics.fbdev.Fbdev"
    }

    fn description(&self) -> &'static str {
        "Extract framebuffers from the fbdev graphics subsystem"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new("dump", "Dump framebuffers", RequirementKind::Bool)
                .with_default(ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Address", ColumnType::UInt),
            Column::string("Device"),
            Column::string("ID"),
            Column::int("Size"),
            Column::string("Virtual resolution"),
            Column::int("BPP"),
            Column::string("State"),
            Column::string("Filename"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let dump = config.get_bool("dump").unwrap_or(false);
        let mut grid = TreeGrid::new(self.columns());

        // The count and the table are two separate symbols. Without the count
        // there is no way to know how much of the table is in use.
        let Ok(registered) = context
            .object_from_symbol(&kernel, "num_registered_fb", None)
            .and_then(|value| value.as_u64())
        else {
            log::error!(
                "\"num_registered_fb\" symbol does not exist in the symbol table. This means \
                 you are either analyzing an unsupported kernel version, your symbol table is \
                 corrupt, or the fbdev driver is compiled as a kernel module."
            );
            return Ok(grid);
        };
        if registered < 1 {
            log::info!("No registered framebuffer in the fbdev API.");
            return Ok(grid);
        }

        let table = context.symbol_offset(&kernel, "registered_fb")?;
        let pointer_size = context
            .symbol_space
            .table(&kernel.symbol_table_name)
            .map(|table| table.pointer_size() as u64)
            .unwrap_or(8);
        let template = context.symbol_space.get_type(&kernel.qualified("fb_info"))?;

        for index in 0..registered {
            let Ok(raw) = context.layers.read(
                &kernel.layer_name,
                table + index * pointer_size,
                pointer_size as usize,
                false,
            ) else {
                continue;
            };
            let mut address = [0u8; 8];
            address[..raw.len()].copy_from_slice(&raw);
            let address = u64::from_le_bytes(address);
            if address == 0 {
                continue;
            }

            let info =
                context.object_from_template(template.clone(), &kernel.layer_name, address);
            let framebuffer = Framebuffer::parse(&info);

            let file = if dump {
                framebuffer.dump(&context, &kernel)
            } else {
                Value::string("Disabled")
            };

            // The device is named by the kobject the driver registered.
            let device = info
                .member("dev")
                .and_then(|device| device.dereference())
                .and_then(|device| device.member("kobj"))
                .and_then(|kobject| kobject.member("name"))
                .ok()
                .and_then(|name| pointer_to_string(&name, 256).ok())
                .map(Value::string)
                .unwrap_or_else(Value::not_available);

            grid.push(
                0,
                vec![
                    // The address reported is where the framebuffer's pixels
                    // live, not where its descriptor does.
                    Value::hex(framebuffer.screen_base),
                    device,
                    match &framebuffer.id {
                        Some(id) => Value::string(id.clone()),
                        None => Value::not_available(),
                    },
                    Value::int(framebuffer.size as i64),
                    Value::string(format!(
                        "{}x{}",
                        framebuffer.width, framebuffer.height
                    )),
                    Value::int(framebuffer.bits as i64),
                    // A suspended framebuffer has been handed to a power state
                    // where its memory may no longer reflect the display.
                    Value::string(if framebuffer.state == 0 {
                        "RUNNING"
                    } else {
                        "SUSPENDED"
                    }),
                    file,
                ],
            )?;
        }
        Ok(grid)
    }
}

/// A framebuffer's parameters, gathered from the two halves of `fb_info`.
///
/// The fixed half describes what the hardware provides and cannot be changed.
/// The variable half describes the mode the driver has it in.
struct Framebuffer {
    id: Option<String>,
    screen_base: u64,
    width: u64,
    height: u64,
    bits: u64,
    /// The virtual height times the length of a line, which covers the parts of
    /// the buffer that are held off screen as well.
    size: u64,
    state: u64,
    /// Where each colour sits inside a pixel, as offset, length and whether the
    /// most significant bit comes first. Absent for a buffer whose format is
    /// described by a FOURCC code rather than by bitfields.
    colors: Option<[(u32, u32, u32); 4]>,
}

impl Framebuffer {
    fn parse(info: &Object) -> Self {
        let fixed = info.member("fix");
        let variable = info.member("var");
        let field = |part: &Result<Object>, name: &str| -> u64 {
            part.as_ref()
                .ok()
                .and_then(|part| part.member(name).ok())
                .and_then(|value| value.as_u64().ok())
                .unwrap_or(0)
        };

        let id = fixed
            .as_ref()
            .ok()
            .and_then(|fixed| fixed.member("id").ok())
            .and_then(|id| id.as_string().ok())
            .filter(|id| !id.is_empty());

        // A grayscale value above one is a FOURCC code naming a packed pixel
        // format, which the bitfields do not describe.
        let grayscale = field(&variable, "grayscale");
        let colors = if grayscale <= 1 {
            variable.as_ref().ok().map(|variable| {
                let bitfield = |name: &str| -> (u32, u32, u32) {
                    let part = variable.member(name);
                    let value = |name: &str| -> u32 {
                        part.as_ref()
                            .ok()
                            .and_then(|part| part.member(name).ok())
                            .and_then(|value| value.as_u64().ok())
                            .unwrap_or(0) as u32
                    };
                    (value("offset"), value("length"), value("msb_right"))
                };
                [
                    bitfield("red"),
                    bitfield("green"),
                    bitfield("blue"),
                    bitfield("transp"),
                ]
            })
        } else {
            let code = fourcc(grayscale);
            log::warn!(
                "Framebuffer \"{}\" uses a FOURCC pixel format \"{code}\" that isn't natively \
                 supported.",
                id.clone().unwrap_or_default()
            );
            None
        };

        let height = field(&variable, "yres_virtual");
        Framebuffer {
            id,
            screen_base: info
                .member("screen_base")
                .and_then(|base| base.pointer_value())
                .unwrap_or(0),
            width: field(&variable, "xres_virtual"),
            height,
            bits: field(&variable, "bits_per_pixel"),
            size: height * field(&fixed, "line_length"),
            state: info
                .member("state")
                .and_then(|state| state.as_u64())
                .unwrap_or(0),
            colors,
        }
    }

    /// Write the buffer out, as an image where its format is understood and as
    /// raw bytes where it is not.
    fn dump(&self, context: &Arc<Context>, kernel: &Module) -> Value {
        let name = self.id.clone().unwrap_or_else(|| "N-A".to_string());
        let base = format!("{name}_{}x{}_{}bpp", self.width, self.height, self.bits);

        let Ok(data) = context.layers.read(
            &kernel.layer_name,
            self.screen_base,
            self.size as usize,
            false,
        ) else {
            log::error!(
                "Layer {} failed to read address {:#x} when dumping framebuffer \"{name}\".",
                kernel.layer_name,
                self.screen_base
            );
            return Value::unreadable();
        };

        let (file, contents) = match &self.colors {
            Some(colors) => (
                format!("{base}.png"),
                crate::framework::png::encode_rgba(
                    self.width as u32,
                    self.height as u32,
                    &to_rgba(&data, self.width, self.height, self.bits, colors),
                ),
            ),
            None => (format!("{base}.raw"), data),
        };

        match crate::framework::plugins::write_extracted(&file, &contents) {
            Ok(_) => Value::string(file),
            Err(_) => Value::unreadable(),
        }
    }
}

/// Unpack a framebuffer's pixels into eight bit red, green, blue and alpha.
///
/// Each pixel is as wide as the mode says and holds its colours at the offsets
/// the bitfields give. A colour the format does not carry is left alone, which
/// leaves an image opaque where it has no alpha channel.
fn to_rgba(
    data: &[u8],
    width: u64,
    height: u64,
    bits: u64,
    colors: &[(u32, u32, u32); 4],
) -> Vec<u8> {
    let bytes = (bits / 8).max(1) as usize;
    let mut pixels = Vec::with_capacity((width * height * 4) as usize);
    let mut offset = 0;

    for _ in 0..height {
        for _ in 0..width {
            let mut raw = [0u8; 8];
            let available = data.len().saturating_sub(offset).min(bytes);
            raw[..available].copy_from_slice(&data[offset..offset + available]);
            let value = u64::from_le_bytes(raw);
            offset += bytes;

            let mut pixel = [0u8, 0, 0, 255];
            for (index, (shift, length, msb_right)) in colors.iter().enumerate() {
                if *length == 0 {
                    continue;
                }
                let mask = (1u64 << length) - 1;
                let mut component = (value >> shift) & mask;
                if *msb_right != 0 {
                    // The bits of this field run the other way round.
                    let mut reversed = 0;
                    for bit in 0..*length {
                        reversed |= ((component >> bit) & 1) << (length - 1 - bit);
                    }
                    component = reversed;
                }
                pixel[index] = component as u8;
            }
            pixels.extend_from_slice(&pixel);
        }
    }
    pixels
}

/// The characters a FOURCC pixel format code spells.
fn fourcc(code: u64) -> String {
    let length = (64 - code.leading_zeros()).div_ceil(8);
    (0..length)
        .map(|index| ((code >> (index * 8)) & 0xff) as u8 as char)
        .collect()
}
