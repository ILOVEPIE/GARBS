package signaturegenerator;

import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;


final class SignatureGenerator {
	
	static final class Signature{
		public byte[] data;
		public byte[] mask;
		public int length;	
		
		public int matches;
		
		public Signature() {
			data = new byte[64];
			mask = new byte[64];
		}
	}
	
	static final class GeneratedResult{
		public Signature signature;
		public int subOffset;
	}
	
	
	private static final class Pattern {
		byte[] data;
		byte[] mask;
		int offset;
		int matches;
	}
	
	private static final Pattern trimSignature(Program prog,Address searchTarget,byte[] data, byte[] mask, int leftCount, int rightCount, int offset, Set<Long> hasTrimmed,Test exitTest) {
		Memory mem = prog.getMemory();
		int fullLeftOffset = (leftCount+offset);
		int fullRightOffset = (offset+64-rightCount);
		long tuple = (((long)(fullLeftOffset)<<32))|(fullRightOffset);
		if(exitTest.check())
			return null;
		if(!hasTrimmed.add(tuple))
			return null;
		if(mask.length-leftCount-rightCount <= 5)
			return null;
		if(((mask.length-leftCount-rightCount)-ArraysHelper.countZeros(mask,leftCount,mask.length-leftCount-rightCount)) <= 5)
			return null;
		int foundCount = 0;
		Address firstFound = null;
		long curByteOffset;
		int fetched;
		byte[] cur_bytes = new byte[2048];
		for(AddressRangeIterator rangeIterator = mem.getAddressRanges(true); rangeIterator.hasNext();) {
			AddressRange range = rangeIterator.next();
			Address startAddress = range.getMinAddress();
			Address endAddress = range.getMaxAddress();
			curByteOffset = -1;
			fetched = 0;
			while(startAddress != null) {
				try {
					//Check for invalid memory
					if(!prog.getAddressFactory().isValidAddress(startAddress))
						break;
					try {
						MemoryBlock block = prog.getMemory().getBlock(startAddress);
						if(!block.isInitialized() || !block.isLoaded()) {
							startAddress = startAddress.getNewAddress(block.getStart().getOffset()+block.getSize());
							continue;
						}
					}catch(Exception e) {
						break;
					}
					//fetch memory
					curByteOffset = startAddress.getOffset();
					long remainingLength = (endAddress.getOffset()-curByteOffset)+1;
					fetched = mem.getBytes(startAddress,cur_bytes,0,(int)(Math.min(2048,remainingLength)));
					int size = mask.length-leftCount-rightCount;
					for (int i = 0; i < fetched-size; i++) {
						boolean internalFound = true;
						for (int index = 0; index < size; index++) {
							if((cur_bytes[i+index] & mask[leftCount+index]) != data[leftCount+index]) {
								internalFound = false;
							}
						}
						if(internalFound) {
							if(firstFound == null)
								firstFound = startAddress.getNewAddress(curByteOffset+i);
							foundCount++;
						}
					}
				} catch(Exception e) {
					e.printStackTrace();
				}
				
				if(startAddress == null || startAddress.getOffset()+fetched > endAddress.getOffset())
					break;
				startAddress = startAddress.getNewAddress(startAddress.getOffset()+fetched);	
			}
		}
		if(foundCount == 0)
			return null;
		if(!searchTarget.equals(firstFound.getNewAddress(firstFound.getOffset()-fullLeftOffset)))
			return null;
		Pattern result;
		Pattern right = trimSignature(prog,searchTarget,data,mask,leftCount,rightCount+1,offset,hasTrimmed,exitTest);
		Pattern left = trimSignature(prog,searchTarget,data,mask,leftCount+1,rightCount,offset,hasTrimmed,exitTest);
		if(right != null && left != null) {
			if(right.data.length+right.matches <= left.data.length+left.matches) {
				result = right;
			} else {
				result = left;
			}
		} else if (right != null && right.matches <= foundCount) {
			result = right;
		} else if (left != null && left.matches <= foundCount) {
			result = left;
		} else {
			result = new Pattern();
			result.data = new byte[mask.length-leftCount-rightCount];
			result.mask = new byte[mask.length-leftCount-rightCount];
			result.offset = leftCount;
			result.matches = foundCount;
			System.arraycopy(data,leftCount,result.data,0,64-leftCount-rightCount);
			System.arraycopy(mask,leftCount,result.mask,0,64-leftCount-rightCount);
		}
		return result;
	}
	
	public static final GeneratedResult generateSignature(Program prog, Address searchTarget, byte[] maskedData, byte[] mask,int offset,Set<Long> set,Test exitTest) {
		
		Pattern pattern = trimSignature(prog,searchTarget,maskedData,mask,0,0,offset,set,exitTest);
		if(pattern == null)
			return null;
		Signature signature = new Signature();
		signature.length = pattern.data.length;
		signature.matches = pattern.matches;
		System.arraycopy(pattern.data, 0, signature.data, 0, pattern.data.length);
		System.arraycopy(pattern.mask, 0, signature.mask, 0, pattern.mask.length);
		GeneratedResult output = new GeneratedResult();
		output.signature = signature;
		output.subOffset = pattern.offset;
		return output;
	}
}
