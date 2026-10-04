//! Render a block of bytes as instructions.
//!
//! Indicates that the bytes provided should be disassembled, based on the
//! architecture.
//!
//! The reference implementation hands a block to capstone and prints one line
//! per instruction, stopping at the first byte it cannot decode. The same
//! library decodes the block here, so the two agree character for character.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use capstone::arch::x86::X86OperandType;
use capstone::arch::{ArchDetail, BuildsCapstone, DetailsArchInsn};
use capstone::{AccessType, Capstone, Insn, RegId};

/// A decoder for one of the four architectures upstream names, or nothing for
/// a name it does not know.
///
/// The possible architectures are `intel`, `intel64`, `arm` and `arm64`.
///
/// Detail is wanted only where an instruction's registers are inspected, and
/// gathering it costs enough to be worth asking for.
pub fn decoder(architecture: &str, detail: bool) -> Option<Capstone> {
    use capstone::arch::arm::ArchMode as ArmMode;
    use capstone::arch::arm64::ArchMode as Arm64Mode;
    use capstone::arch::x86::ArchMode as X86Mode;

    let built = match architecture {
        "intel" => Capstone::new()
            .x86()
            .mode(X86Mode::Mode32)
            .detail(detail)
            .build(),
        "intel64" => Capstone::new()
            .x86()
            .mode(X86Mode::Mode64)
            .detail(detail)
            .build(),
        "arm" => Capstone::new()
            .arm()
            .mode(ArmMode::Arm)
            .detail(detail)
            .build(),
        "arm64" => Capstone::new()
            .arm64()
            .mode(Arm64Mode::Arm)
            .detail(detail)
            .build(),
        _ => return None,
    };
    built.ok()
}

/// The instructions a block holds, as the reference implementation prints them.
///
/// Each instruction is written on its own line, preceded by a newline, which
/// leaves the column opening with a blank line exactly as upstream's does. An
/// architecture this does not know leaves the column empty, which is what
/// upstream produces for a block whose architecture was never set.
pub fn text(data: &[u8], offset: u64, architecture: &str) -> String {
    let Some(decoder) = decoder(architecture, false) else {
        return String::new();
    };
    let Ok(instructions) = decoder.disasm_all(data, offset) else {
        return String::new();
    };

    let mut output = String::new();
    for instruction in instructions.iter() {
        output.push_str(&format!(
            "\n{:#x}:\t{}\t{}",
            instruction.address(),
            instruction.mnemonic().unwrap_or_default(),
            instruction.op_str().unwrap_or_default()
        ));
    }
    output
}

/// The registers an instruction writes to, named the way capstone names them.
///
/// Both the writes an instruction carries implicitly and the register operands
/// the decoder marked as written are counted, which is what capstone's own
/// `regs_access` reports.
pub fn registers_written(decoder: &Capstone, instruction: &Insn) -> Vec<String> {
    let Ok(detail) = decoder.insn_detail(instruction) else {
        return Vec::new();
    };
    let mut written: Vec<RegId> = detail.regs_write().to_vec();
    if let ArchDetail::X86Detail(x86) = detail.arch_detail() {
        for operand in x86.operands() {
            let X86OperandType::Reg(register) = operand.op_type else {
                continue;
            };
            let writes = matches!(
                operand.access,
                Some(AccessType::WriteOnly) | Some(AccessType::ReadWrite)
            );
            if writes && !written.contains(&register) {
                written.push(register);
            }
        }
    }
    written
        .into_iter()
        .filter_map(|register| decoder.reg_name(register))
        .collect()
}

/// Whether every byte of an instruction's opcode is zero, which is how a run
/// of zeroed memory is told apart from code.
pub fn opcode_is_zero(decoder: &Capstone, instruction: &Insn) -> bool {
    let Ok(detail) = decoder.insn_detail(instruction) else {
        return false;
    };
    match detail.arch_detail() {
        ArchDetail::X86Detail(x86) => x86.opcode().iter().all(|byte| *byte == 0),
        _ => false,
    }
}
