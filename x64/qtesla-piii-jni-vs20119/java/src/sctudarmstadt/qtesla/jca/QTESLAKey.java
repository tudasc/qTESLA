package sctudarmstadt.qtesla.jca;


import java.util.Arrays;

public class QTESLAKey {
	private byte[] _key_data;
	private int _key_len;
	
	public QTESLAKey (byte[] key_data) {
		this._key_data = key_data;
		this._key_len = _key_data.length;		
	}
	
	public QTESLAKey () {
		this._key_data = new byte[0];
		this._key_len = 0;		
	}
	
	public int getKeyLen () {
		return this._key_len;
	}
	
	public byte[] getBytesOfKey() {
		return _key_data;
	}
	
	public byte[] getEncoded() {
		return _key_data;
	}
	
	public String toString() {
	    return getClass().getName() + "@" + Arrays.toString(_key_data);
	}
}
