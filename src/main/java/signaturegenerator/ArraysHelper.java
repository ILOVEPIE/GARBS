package signaturegenerator;

import java.util.Arrays;

import ghidra.util.Msg;

import java.lang.reflect.Array;

final class ArraysHelper {
	
	static <T> T concat(T array1, T array2) {
	    if (!array1.getClass().isArray() || !array2.getClass().isArray()) {
	        throw new IllegalArgumentException("Only arrays are accepted.");
	    }

	    Class<?> compType1 = array1.getClass().getComponentType();
	    Class<?> compType2 = array2.getClass().getComponentType();

	    if (!compType1.equals(compType2)) {
	        throw new IllegalArgumentException("Two arrays have different types.");
	    }

	    int len1 = Array.getLength(array1);
	    int len2 = Array.getLength(array2);

	    @SuppressWarnings("unchecked")
	    //the cast is safe due to the previous checks
	    T result = (T) Array.newInstance(compType1, len1+len2);

	    System.arraycopy(array1, 0, result, 0, len1);
	    System.arraycopy(array2, 0, result, len1, len2);

	    return result;
	}

	public static void printHexArray(Object origin,byte[] data) {
		StringBuilder builder = new StringBuilder();
		boolean first = true;
		for(int i = 0; i < data.length; i++) {
			if(!first) {
				builder.append(" ");
			} else
				first = false;
			builder.append(String.format("%02X",data[i]).toUpperCase());
		}
		Msg.info(origin, builder.toString());
	}

	public static int countZeros(byte[] arr,int start,int end) {
		int total = 0;
		for(int i = start; i < arr.length && i < end; i++) {
			if(arr[i] == 0)
				total++;
		}
		return total;
	}

}
