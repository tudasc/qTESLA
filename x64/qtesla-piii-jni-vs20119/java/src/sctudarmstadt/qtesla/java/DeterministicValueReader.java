package sctudarmstadt.qtesla.java;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class DeterministicValueReader {
	public static int readPKandSK(byte[] pk, byte[] sk ) {
		
		int ret = setValFromFileByte (pk, "===PublicKey-signed===");
		if(ret != 0)
			return ret;

		
		ret = setValFromFileByte (sk, "===SecretKey-signed===");
		if(ret != 0)
			return ret;
		
		return ret;
	}
	
	public static int readR_IandR(byte[] ri, byte[] r ) {
		int ret = setValFromFileByte (ri, "===randomness_input-signed===");
		if(ret != 0)
			return ret;	
		
		ret = setValFromFileByte (r, "===randomness-signed===");
		if(ret != 0)
			return ret;
		
		return ret;
	}
	
	public static int readA(int[] A) {
		int ret = setValFromFileInt (A, "===A===");
		if(ret != 0)
			return ret;	
		
		return ret;
	}
	
	public static int readY(int[] Y) {
		int ret = setValFromFileInt (Y, "===Y===");
		if(ret != 0)
			return ret;	
		
		return ret;
	}
	
	@SuppressWarnings("unchecked")
	public static int setValFromFileLong (long[] out_arr, String categorie) {	
		BufferedReader reader;
		
		try {
			reader = new BufferedReader(new FileReader(	"FirstOutput.txt" ));
			
			String line = reader.readLine();
			//int status = 0;
			while (line != null) {
			
				if(line.compareTo(categorie) == 0) {
					// Read the size in the next line
					line = reader.readLine();
					String[] size_arr = line.split(" ");
					
					if(size_arr.length !=3) {
						System.err.print("PublicKey has not valid length line.\n");
						reader.close();
						return 1100;
					}
					
					int linecnt; 
				    try
				    {
				    	linecnt = Integer.parseInt(size_arr[1]);
				    }
				    
				    catch (NumberFormatException nfe) {
				    	System.out.println("NumberFormatException: " + nfe.getMessage());
						reader.close();
						return 1101;
				    }
				    
				    // Check if provided array and file have the same number of lines
				    if(out_arr.length != linecnt) {
				    	System.err.print("Size mismatch between file and array.\n");
				    	reader.close();
				    	return 1102;
				    }
				    
				    // Run over all lines and fill the array
				    for(int li=0; li < linecnt; li++) {
						// read next line
						line = reader.readLine();		
						Long val = Long.parseLong(line);
						out_arr[li] = val;				
				    }
					
				    // Everything should be read
					//status = 1;
					}
				
				// read next line
				line = reader.readLine();
			}
			
			
			reader.close();
		} 
		catch (IOException e) {
			e.printStackTrace();
		}
		
		return 0;
	}
	
	public static int setValFromFileInt (int[] out_arr, String categorie) {	
		BufferedReader reader;
		
		try {
			reader = new BufferedReader(new FileReader(	"FirstOutput.txt" ));
			
			String line = reader.readLine();
			//int status = 0;
			while (line != null) {
			
				if(line.compareTo(categorie) == 0) {
					// Read the size in the next line
					line = reader.readLine();
					String[] size_arr = line.split(" ");
					
					if(size_arr.length !=3) {
						System.err.print("PublicKey has not valid length line.\n");
						reader.close();
						return 1100;
					}
					
					int linecnt; 
				    try
				    {
				    	linecnt = Integer.parseInt(size_arr[1]);
				    }
				    
				    catch (NumberFormatException nfe) {
				    	System.out.println("NumberFormatException: " + nfe.getMessage());
						reader.close();
						return 1101;
				    }
				    
				    // Check if provided array and file have the same number of lines
				    if(out_arr.length != linecnt) {
				    	System.err.print("Size mismatch between file and array.\n");
				    	reader.close();
				    	return 1102;
				    }
				    
				    // Run over all lines and fill the array
				    for(int li=0; li < linecnt; li++) {
						// read next line
						line = reader.readLine();		
						Integer val = Integer.parseInt(line);
						out_arr[li] = val;				
				    }
					
				    // Everything should be read
					//status = 1;
					}
				
				// read next line
				line = reader.readLine();
			}
			
			
			reader.close();
		} 
		catch (IOException e) {
			e.printStackTrace();
		}
		
		return 0;
	}
	
	@SuppressWarnings("unchecked")
	public static int setValFromFileByte (byte[] out_arr, String categorie) {	
		BufferedReader reader;
		
		try {
			reader = new BufferedReader(new FileReader(	"FirstOutput.txt" ));
			
			String line = reader.readLine();
			//int status = 0;
			while (line != null) {
			
				if(line.compareTo(categorie) == 0) {
					// Read the size in the next line
					line = reader.readLine();
					String[] size_arr = line.split(" ");
					
					if(size_arr.length !=3) {
						System.err.print("PublicKey has not valid length line.\n");
						reader.close();
						return 1100;
					}
					
					int linecnt; 
				    try
				    {
				    	linecnt = Integer.parseInt(size_arr[1]);
				    }
				    
				    catch (NumberFormatException nfe) {
				    	System.out.println("NumberFormatException: " + nfe.getMessage());
						reader.close();
						return 1101;
				    }
				    
				    // Check if provided array and file have the same number of lines
				    if(out_arr.length != linecnt) {
				    	System.err.print("Size mismatch between file and array.\n");
				    	reader.close();
				    	return 1102;
				    }
				    
				    // Run over all lines and fill the array
				    for(int li=0; li < linecnt; li++) {
						// read next line
						line = reader.readLine();		
						Byte val = Byte.parseByte(line);
						out_arr[li] = val;				
				    }
					
				    // Everything should be read
					//status = 1;
					}
				
				// read next line
				line = reader.readLine();
			}
			
			
			reader.close();
		} 
		catch (IOException e) {
			e.printStackTrace();
		}
		
		return 0;
	}
	
	
	public static void setRandomAndRandomInputAndA (int[] ri, int[] r, int[] a) {
		
	}
	
	public static void setY (int[] y) {
		
	}
}
