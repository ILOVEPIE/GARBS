package signaturegenerator;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;

final class MaskingChecks {

	public static boolean checkIfJumpsExternal(AddressRange functionRange,Instruction inst) {
		if(!inst.isFallthrough()) {
			Address[] flowTargets = inst.getFlows();
			for(int i = 0; i < flowTargets.length;i++) {
				if(!functionRange.contains(flowTargets[i]))
					return true;
			}
		}
		return false;
	}
	
	public static boolean checkIfAccessesExteriorMemory(AddressRange functionRange,Instruction inst) {
		Object[] output = inst.getResultObjects();
		for(int i = 0; i < output.length; i++) {
			if(output[i] instanceof Address) {
				Address addr = (Address)output[i];
				if(!functionRange.contains(addr))
					return true;
			}
		}
		Object[] input = inst.getInputObjects();
		for(int i = 0; i < input.length; i++) {
			if(input[i] instanceof Address) {
				Address addr = (Address)input[i];
				if(!functionRange.contains(addr))
					return true;
			}
		}
		return false;
	}

	public static boolean checkIfReferencesPointerRegisters(Instruction inst) {
		Object[] output = inst.getResultObjects();
		for(int i = 0; i < output.length; i++) {
			if(output[i] instanceof Register) {
				Register reg = (Register)output[i];
				if(reg.isProgramCounter() || reg.followsFlow() || reg.isDefaultFramePointer())
					return true;
			}
		}
		return false;
	}

	public static boolean checkIfScalarCouldBeAddress(Program prog, Instruction inst, int i) {
		Object[] opObjects = inst.getOpObjects(i);
		for(int j = 0; j < opObjects.length; j++) {
			if(opObjects[j] instanceof Scalar) {
				Scalar scalar = (Scalar)opObjects[j];
				if(prog.getMemory().contains(prog.getAddressMap().decodeAddress(scalar.getUnsignedValue())))
					return true;
			}
		}
		return false;
	}
}
