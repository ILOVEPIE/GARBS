package signaturegenerator;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Mask;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

final class SignatureGenerationHelper {

	static final class MaskedData {
		public byte[] data;
		public byte[] mask;
	}

	public static SignatureGenerationHelper.MaskedData maskData(Program prog, Address genStartAddress,
			Address genEndAddress) throws MemoryAccessException {
		AddressRange functionRange = new AddressRangeImpl(genStartAddress,genEndAddress);
		Listing listing = prog.getListing();
		byte[] maskedBytes = new byte[0];
		byte[] mask = new byte[0];
		Address current = genStartAddress;
		while(current.getOffset() < genEndAddress.getOffset()) {
			Instruction inst = listing.getInstructionAt(current);
			if(inst == null) {
				inst = listing.getInstructionContaining(current);
				if(inst == null) {
					byte[] onebyte = new byte[] {prog.getMemory().getByte(current)};
					maskedBytes = ArraysHelper.concat(maskedBytes, onebyte);
					mask = ArraysHelper.concat(mask, onebyte);
					current = current.add(1);
				} else {
					boolean accessesExternal = MaskingChecks.checkIfAccessesExteriorMemory(functionRange, inst);
					boolean jumpsExternal = MaskingChecks.checkIfJumpsExternal(functionRange,inst);
					boolean referencesPointerRegisters = MaskingChecks.checkIfReferencesPointerRegisters(inst);
					Address instructionAddress = inst.getAddress();
					int operandCount = inst.getNumOperands();
					byte[] instructionData = inst.getBytes();
					byte[] localMask = new byte[instructionData.length];
					for(int i = 0; i < localMask.length; i++) localMask[i] = -1;
					for(int i = 0; i < operandCount; i++) {
						int operandType = inst.getOperandType(i);
						boolean maskOpcode = false;
						if((operandType & OperandType.ADDRESS) != 0) {
							if((operandType & OperandType.IMMEDIATE) != 0)
								maskOpcode |= true;
							if(jumpsExternal)
								maskOpcode |= true;
							if(accessesExternal)
								maskOpcode |= true;
						}
						if((operandType & OperandType.SCALAR) != 0) {
							if(referencesPointerRegisters)
								maskOpcode |= true;
							if((operandType & OperandType.IMMEDIATE) != 0)
								maskOpcode |= MaskingChecks.checkIfScalarCouldBeAddress(prog,inst,i);
						}
						if(maskOpcode) {
							Mask operandMask = inst.getPrototype().getOperandValueMask(i);
							byte[] maskBytes = operandMask.getBytes();
							for(int j = 0; j < maskBytes.length; j++) {
								localMask[j] = (byte)((~maskBytes[j]) == -1?-1:0);
							}
							
							for(int j = 0; j < maskBytes.length; j++) {
								instructionData[j] &= localMask[j];
							}
						}
					}
					int offset = (int)(current.getOffset()-instructionAddress.getOffset());
					byte[] maskedDataClipped = new byte[instructionData.length-(offset+1)];
					byte[] maskClipped = new byte[instructionData.length-(offset+1)];
					System.arraycopy(instructionData, offset, maskedDataClipped, 0, instructionData.length-(offset+1));
					System.arraycopy(localMask, offset, maskClipped, 0, instructionData.length-(offset+1));
					maskedBytes = ArraysHelper.concat(maskedBytes, maskedDataClipped);
					mask = ArraysHelper.concat(mask, maskClipped);
					current = current.add(instructionData.length-(offset+1));
				}
				continue;
			}
			int operandCount = inst.getNumOperands();
			boolean accessesExternal = MaskingChecks.checkIfAccessesExteriorMemory(functionRange, inst);
			boolean jumpsExternal = MaskingChecks.checkIfJumpsExternal(functionRange,inst);
			boolean referencesPointerRegisters = MaskingChecks.checkIfReferencesPointerRegisters(inst);
			byte[] instructionData = inst.getBytes();
			byte[] localMask = new byte[instructionData.length];
			for(int i = 0; i < localMask.length; i++) localMask[i] = -1;
			for(int i = 0; i < operandCount; i++) {
				int operandType = inst.getOperandType(i);
				boolean maskOpcode = false;
				if((operandType & OperandType.ADDRESS) != 0) {
					if((operandType & OperandType.IMMEDIATE) != 0)
						maskOpcode |= true;
					if(jumpsExternal)
						maskOpcode |= true;
					if(accessesExternal)
						maskOpcode |= true;
				}
				if((operandType & OperandType.SCALAR) != 0) {
					if(referencesPointerRegisters)
						maskOpcode |= true;
					if((operandType & OperandType.IMMEDIATE) != 0)
						maskOpcode |= MaskingChecks.checkIfScalarCouldBeAddress(prog,inst,i);
				}
				if(maskOpcode) {
					Mask operandMask = inst.getPrototype().getOperandValueMask(i);
					byte[] maskBytes = operandMask.getBytes();
					for(int j = 0; j < maskBytes.length; j++) {
						localMask[j] = (byte)((~maskBytes[j]) == -1?-1:0);
					}
					
					for(int j = 0; j < maskBytes.length; j++) {
						instructionData[j] &= localMask[j];
					}
				}
			}
			
			mask = ArraysHelper.concat(mask, localMask);
			maskedBytes = ArraysHelper.concat(maskedBytes, instructionData);
			current = current.add(instructionData.length);
		}
		MaskedData result = new MaskedData();
		result.mask = mask;
		result.data = maskedBytes;
		return result;
	}

}
