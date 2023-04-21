package signaturegenerator;

final class Hasher {
	private static final long crc_polynomial = 0xC96C5795D7870F42L;
	
	private static final long fnv1a_offset_basis = 0xCBF29CE484222325L;
	
	private static final long fnv1a_prime = 0x100000001B3L;
	
	private static boolean initialized = false;
	
	private static final long[] table = new long[256];
	
	private static void initialize() {
		for(int i = 0; i < 256; i++) {
			long crc = i;
			for (int j = 0; j < 8; j++) {
				if((crc & 1) > 0) {
					crc = crc >>> 1;
					crc ^= crc_polynomial;
				}else {
					crc = crc >>> 1;
				}
			}
			
			table[i] = crc;
		}
		initialized = true;
	}
	
	public static final long fnv1a64(byte[] bytes) {
		long hash = fnv1a_offset_basis;
		for (int i = 0; i < bytes.length; i++) {
			hash ^= bytes[i];
			hash *= fnv1a_prime;
		}
		return hash;
	}
	
	private static final Object initSyncObj = new Object();
	
	public static final long crc64(byte[] bytes) {
		synchronized(initSyncObj) {
			if(!initialized)initialize();
		}
		long crc = 0;
		for (int i = 0; i < bytes.length; i++) {
			int index = (int) ((bytes[i] ^ crc) & 0xFF);
			long lookup = table[index];
			
			crc = crc >>> 8;
			crc ^= lookup;
		}
		return crc;
	}
}
