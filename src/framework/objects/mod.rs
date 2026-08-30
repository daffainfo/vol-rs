//! Objects: typed views onto bytes in a layer.
//!
//! An `Object` pairs a template with a location, a layer and an offset. It
//! reads lazily, so constructing one costs nothing and walking a large
//! structure only touches the bytes actually asked for.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

pub mod template;
pub mod utility;

use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::Context;
use crate::framework::objects::template::{
    read_signed, read_unsigned, Encoding, Template,
};
use crate::framework::symbols::isf::Endian;

/// Where an object lives and what type it has.
#[derive(Clone)]
pub struct ObjectInfo {
    pub layer_name: String,
    /// The layer this object's pointers refer to.
    ///
    /// Usually the layer the object itself lives in, but a structure read out
    /// of physical memory still holds kernel virtual addresses, so the two are
    /// kept apart.
    pub native_layer_name: String,
    pub offset: u64,
    pub type_name: String,
    /// The member name this object was reached by, when it came from a struct.
    pub member_name: Option<String>,
    /// The object this one was read out of, for plugins that report context.
    pub parent: Option<Arc<Object>>,
}

/// A typed value located in a layer.
#[derive(Clone)]
pub struct Object {
    context: Arc<Context>,
    template: Arc<Template>,
    info: ObjectInfo,
}

impl Object {
    /// Create an object at `offset` in `layer_name` with the given template.
    pub fn new(
        context: Arc<Context>,
        template: Arc<Template>,
        layer_name: impl Into<String>,
        offset: u64,
    ) -> Self {
        let type_name = template.type_name();
        let layer_name = layer_name.into();
        // Normalise the offset the way the reference implementation does, so an
        // object's offset and a pointer to it compare equal.
        let offset = offset & context.layers.address_mask(&layer_name);
        Self {
            context,
            template,
            info: ObjectInfo {
                native_layer_name: layer_name.clone(),
                layer_name,
                offset,
                type_name,
                member_name: None,
                parent: None,
            },
        }
    }

    /// Location and type metadata, mirroring the `vol` attribute plugins use.
    pub fn vol(&self) -> &ObjectInfo {
        &self.info
    }

    pub fn context(&self) -> &Arc<Context> {
        &self.context
    }

    pub fn template(&self) -> &Arc<Template> {
        &self.template
    }

    pub fn offset(&self) -> u64 {
        self.info.offset
    }

    pub fn layer_name(&self) -> &str {
        &self.info.layer_name
    }

    /// The layer this object's pointers are read against.
    pub fn native_layer_name(&self) -> &str {
        &self.info.native_layer_name
    }

    pub fn type_name(&self) -> &str {
        &self.info.type_name
    }

    /// The template with any reference expanded.
    pub fn resolved_template(&self) -> Result<Arc<Template>> {
        self.context.symbol_space.resolve(&self.template)
    }

    /// Size in bytes of this object.
    pub fn size(&self) -> Result<u64> {
        self.context.symbol_space.size_of(&self.template)
    }

    /// The raw bytes backing this object.
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let size = self.size()? as usize;
        if size == 0 {
            return Ok(Vec::new());
        }
        self.context
            .layers
            .read(&self.info.layer_name, self.info.offset, size, false)
    }

    /// Read this object as an unsigned integer.
    ///
    /// Works for integers, chars, booleans, pointers, enumerations and
    /// bitfields. Anything else is a type error.
    pub fn as_u64(&self) -> Result<u64> {
        let template = self.resolved_template()?;
        match template.as_ref() {
            Template::Integer { size, endian, .. } => {
                let data = self.read_exact(*size)?;
                Ok(read_unsigned(&data, *endian))
            }
            Template::Char { size, .. } => {
                let data = self.read_exact(*size)?;
                Ok(read_unsigned(&data, Endian::Little))
            }
            Template::Pointer { size, endian, .. } => {
                let data = self.read_exact(*size)?;
                // A pointer always names somewhere within its own layer, so the
                // bits the layer does not address are not part of the value.
                let mask = self
                    .context
                    .layers
                    .address_mask(&self.info.native_layer_name);
                Ok(read_unsigned(&data, *endian) & mask)
            }
            Template::Bool { size } => {
                let data = self.read_exact(*size)?;
                Ok(read_unsigned(&data, Endian::Little))
            }
            Template::Enumeration(enumeration) => {
                let data = self.read_exact(enumeration.size)?;
                Ok(read_unsigned(&data, enumeration.endian))
            }
            Template::Bitfield {
                base,
                start_bit,
                end_bit,
            } => {
                let size = self.context.symbol_space.size_of(base)? as usize;
                let data = self.read_exact(size)?;
                let raw = read_unsigned(&data, Endian::Little);
                let width = end_bit - start_bit;
                if width == 0 || width >= 64 {
                    return Ok(raw >> start_bit);
                }
                Ok((raw >> start_bit) & ((1u64 << width) - 1))
            }
            other => Err(VolatilityError::Other(format!(
                "Cannot read '{}' as an integer",
                other.type_name()
            ))),
        }
    }

    /// The value exactly as stored, before the layer's addressing narrows it.
    ///
    /// A pointer read normally loses the bits the layer cannot address, which
    /// is what makes it usable as an address. A few kernel fields hide other
    /// data in those bits and need them back.
    pub fn raw_value(&self) -> Result<u64> {
        let template = self.resolved_template()?;
        match template.as_ref() {
            Template::Pointer { size, endian, .. } | Template::Integer { size, endian, .. } => {
                let data = self.read_exact(*size)?;
                Ok(read_unsigned(&data, *endian))
            }
            _ => self.as_u64(),
        }
    }

    /// Read this object as a signed integer.
    pub fn as_i64(&self) -> Result<i64> {
        let template = self.resolved_template()?;
        match template.as_ref() {
            Template::Integer {
                size,
                signed,
                endian,
            } => {
                let data = self.read_exact(*size)?;
                Ok(if *signed {
                    read_signed(&data, *endian)
                } else {
                    read_unsigned(&data, *endian) as i64
                })
            }
            Template::Char { size, signed } => {
                let data = self.read_exact(*size)?;
                Ok(if *signed {
                    read_signed(&data, Endian::Little)
                } else {
                    read_unsigned(&data, Endian::Little) as i64
                })
            }
            Template::Enumeration(enumeration) => {
                let data = self.read_exact(enumeration.size)?;
                Ok(if enumeration.signed {
                    read_signed(&data, enumeration.endian)
                } else {
                    read_unsigned(&data, enumeration.endian) as i64
                })
            }
            _ => Ok(self.as_u64()? as i64),
        }
    }

    /// Read this object as a floating point value.
    pub fn as_f64(&self) -> Result<f64> {
        let template = self.resolved_template()?;
        match template.as_ref() {
            Template::Float { size, endian } => {
                let data = self.read_exact(*size)?;
                Ok(match (size, endian) {
                    (4, Endian::Little) => f32::from_le_bytes(data[..4].try_into().unwrap()) as f64,
                    (4, Endian::Big) => f32::from_be_bytes(data[..4].try_into().unwrap()) as f64,
                    (8, Endian::Big) => f64::from_be_bytes(data[..8].try_into().unwrap()),
                    _ => f64::from_le_bytes(data[..8].try_into().unwrap()),
                })
            }
            other => Err(VolatilityError::Other(format!(
                "Cannot read '{}' as a float",
                other.type_name()
            ))),
        }
    }

    pub fn as_bool(&self) -> Result<bool> {
        Ok(self.as_u64()? != 0)
    }

    /// The name of this enumeration's current value.
    pub fn enum_name(&self) -> Result<String> {
        let template = self.resolved_template()?;
        let enumeration = template.as_enum().ok_or_else(|| {
            VolatilityError::Other(format!("'{}' is not an enumeration", template.type_name()))
        })?;
        Ok(enumeration.lookup(self.as_i64()?))
    }

    /// Read a string, stopping at the first NUL.
    ///
    /// Accepts `String` templates and arrays of character-sized elements, which
    /// is how fixed-size name fields are usually declared.
    pub fn as_string(&self) -> Result<String> {
        let template = self.resolved_template()?;
        match template.as_ref() {
            Template::String {
                max_length,
                encoding,
            } => {
                let width = match encoding {
                    Encoding::Utf8 => 1,
                    Encoding::Utf16Le => 2,
                };
                let data = self.read_exact(max_length * width)?;
                Ok(decode_string(&data, *encoding))
            }
            Template::Array { count, subtype } => {
                let element_size = self.context.symbol_space.size_of(subtype)? as usize;
                let data = self.read_exact(*count as usize * element_size.max(1))?;
                let encoding = if element_size == 2 {
                    Encoding::Utf16Le
                } else {
                    Encoding::Utf8
                };
                Ok(decode_string(&data, encoding))
            }
            Template::Bytes { length } => {
                let data = self.read_exact(*length)?;
                Ok(decode_string(&data, Encoding::Utf8))
            }
            other => Err(VolatilityError::Other(format!(
                "Cannot read '{}' as a string",
                other.type_name()
            ))),
        }
    }

    /// Whether the struct has a member of this name, following anonymous
    /// members.
    pub fn has_member(&self, name: &str) -> bool {
        self.context
            .symbol_space
            .find_member(&self.template, name)
            .map(|found| found.is_some())
            .unwrap_or(false)
    }

    /// A member of this struct or union.
    pub fn member(&self, name: &str) -> Result<Object> {
        let (offset, template) = self
            .context
            .symbol_space
            .find_member(&self.template, name)?
            .ok_or_else(|| {
                VolatilityError::Other(format!(
                    "'{}' has no member '{name}'",
                    self.info.type_name
                ))
            })?;

        let type_name = template.type_name();
        Ok(Object {
            context: self.context.clone(),
            template,
            info: ObjectInfo {
                layer_name: self.info.layer_name.clone(),
                native_layer_name: self.info.native_layer_name.clone(),
                offset: self.info.offset + offset,
                type_name,
                member_name: Some(name.to_string()),
                parent: Some(Arc::new(self.clone())),
            },
        })
    }

    /// Every member name of this struct, in offset order.
    pub fn member_names(&self) -> Result<Vec<String>> {
        let template = self.resolved_template()?;
        Ok(template
            .as_struct()
            .map(|structure| {
                structure
                    .member_names()
                    .into_iter()
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Number of elements, for arrays.
    pub fn count(&self) -> Result<u64> {
        let template = self.resolved_template()?;
        match template.as_ref() {
            Template::Array { count, .. } => Ok(*count),
            other => Err(VolatilityError::Other(format!(
                "'{}' is not an array",
                other.type_name()
            ))),
        }
    }

    /// One element of an array.
    pub fn index(&self, position: u64) -> Result<Object> {
        let template = self.resolved_template()?;
        let Template::Array { count, subtype } = template.as_ref() else {
            return Err(VolatilityError::Other(format!(
                "'{}' is not an array",
                template.type_name()
            )));
        };
        if position >= *count {
            return Err(VolatilityError::Other(format!(
                "Index {position} is out of range for an array of {count}"
            )));
        }
        let element_size = self.context.symbol_space.size_of(subtype)?;
        let type_name = subtype.type_name();
        Ok(Object {
            context: self.context.clone(),
            template: subtype.clone(),
            info: ObjectInfo {
                layer_name: self.info.layer_name.clone(),
                native_layer_name: self.info.native_layer_name.clone(),
                offset: self.info.offset + position * element_size,
                type_name,
                member_name: None,
                parent: Some(Arc::new(self.clone())),
            },
        })
    }

    /// Iterate an array's elements.
    pub fn iter_array(&self) -> Result<Vec<Object>> {
        let count = self.count()?;
        (0..count).map(|position| self.index(position)).collect()
    }

    /// Re-interpret the same bytes as a different type, given as `table!name`.
    pub fn cast(&self, type_name: &str) -> Result<Object> {
        let template = self.context.symbol_space.get_type(type_name)?;
        Ok(self
            .rebuild(template, self.info.offset))
    }

    /// Re-interpret the same bytes using an already-built template.
    pub fn cast_template(&self, template: Arc<Template>) -> Object {
        self.rebuild(template, self.info.offset)
    }

    /// Another object in the same pair of layers.
    fn rebuild(&self, template: Arc<Template>, offset: u64) -> Object {
        let mut object = Object::new(
            self.context.clone(),
            template,
            self.info.layer_name.clone(),
            offset,
        );
        object.info.native_layer_name = self.info.native_layer_name.clone();
        object
    }

    /// The same object, with its pointers read against `layer`.
    ///
    /// This is how a structure recovered from physical memory is made usable:
    /// its own bytes come from where it was found, but the addresses it holds
    /// are the kernel's.
    pub fn with_native_layer(mut self, layer: impl Into<String>) -> Object {
        self.info.native_layer_name = layer.into();
        self
    }

    /// The address a pointer holds.
    pub fn pointer_value(&self) -> Result<u64> {
        let template = self.resolved_template()?;
        match template.as_ref() {
            Template::Pointer { size, endian, .. } => {
                let data = self.read_exact(*size)?;
                // Masked for the same reason object offsets are: a pointer only
                // names an address the layer it points into can address, so the
                // two stay directly comparable.
                let mask = self
                    .context
                    .layers
                    .address_mask(&self.info.native_layer_name);
                Ok(read_unsigned(&data, *endian) & mask)
            }
            _ => self.as_u64(),
        }
    }

    pub fn is_null(&self) -> bool {
        self.pointer_value().map(|value| value == 0).unwrap_or(true)
    }

    /// Follow a pointer, producing an object of its subtype.
    pub fn dereference(&self) -> Result<Object> {
        let template = self.resolved_template()?;
        let Template::Pointer { subtype, .. } = template.as_ref() else {
            return Err(VolatilityError::Other(format!(
                "'{}' is not a pointer",
                template.type_name()
            )));
        };
        let address = self.pointer_value()?;
        if address == 0 {
            return Err(VolatilityError::invalid_address(
                &self.info.layer_name,
                0,
                "Cannot dereference a null pointer",
            ));
        }
        let type_name = subtype.type_name();
        Ok(Object {
            context: self.context.clone(),
            template: subtype.clone(),
            info: ObjectInfo {
                // A pointer names an address in the native layer, which is
                // where the object it refers to is therefore built.
                layer_name: self.info.native_layer_name.clone(),
                native_layer_name: self.info.native_layer_name.clone(),
                offset: address,
                type_name,
                member_name: None,
                parent: Some(Arc::new(self.clone())),
            },
        })
    }

    /// Follow a pointer, re-typing the target as `type_name`.
    pub fn dereference_as(&self, type_name: &str) -> Result<Object> {
        let address = self.pointer_value()?;
        let template = self.context.symbol_space.get_type(type_name)?;
        Ok(Object::new(
            self.context.clone(),
            template,
            self.info.native_layer_name.clone(),
            address,
        ))
    }

    /// Whether the object's bytes can actually be read.
    pub fn is_readable(&self) -> bool {
        match self.size() {
            Ok(size) => self.context.layers.is_valid(
                &self.info.layer_name,
                self.info.offset,
                size.max(1),
            ),
            Err(_) => false,
        }
    }

    /// A copy of this object viewed in a different layer.
    pub fn in_layer(&self, layer_name: &str) -> Object {
        let mut clone = self.clone();
        clone.info.layer_name = layer_name.to_string();
        clone
    }

    /// A copy of this object at a different offset.
    pub fn at_offset(&self, offset: u64) -> Object {
        let mut clone = self.clone();
        clone.info.offset = offset & self.context.layers.address_mask(&self.info.layer_name);
        clone
    }

    fn read_exact(&self, length: usize) -> Result<Vec<u8>> {
        if length == 0 {
            return Ok(Vec::new());
        }
        self.context
            .layers
            .read(&self.info.layer_name, self.info.offset, length, false)
    }
}

/// Decode bytes up to the first NUL terminator.
pub fn decode_string(data: &[u8], encoding: Encoding) -> String {
    match encoding {
        Encoding::Utf8 => {
            // Decoded whole, then cut at the first terminator. A byte sequence
            // that is not valid text ends the string just as a NUL does, which
            // is what keeps a smeared field from rendering as replacement
            // characters.
            let decoded = String::from_utf8_lossy(data);
            let end = decoded
                .find(|character| character == '\u{FFFD}' || character == '\0')
                .unwrap_or(decoded.len());
            decoded[..end].to_string()
        }
        Encoding::Utf16Le => {
            let units: Vec<u16> = data
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .take_while(|&unit| unit != 0)
                .collect();
            String::from_utf16_lossy(&units)
        }
    }
}
