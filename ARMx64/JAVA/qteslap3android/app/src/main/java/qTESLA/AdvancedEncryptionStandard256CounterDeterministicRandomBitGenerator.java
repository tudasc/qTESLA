package qTESLA;

import java.util.Arrays;

public class AdvancedEncryptionStandard256CounterDeterministicRandomBitGenerator {

    private byte[] key;
    private byte[] value;
    private int reseedCounter;

    public AdvancedEncryptionStandard256CounterDeterministicRandomBitGenerator () {

        this.key	= new byte[32];
        this.value	= new byte[16];

    }

    public int getReseedCounter () {

        return this.reseedCounter;

    }

    public void setReseedCounter (int reseedCounter) {

        this.reseedCounter = reseedCounter;

    }

    public byte[] getKey () {

        return this.key;

    }

    /********************************************************************
     * Description:	Set A Part of Key to "character"
     *
     * @param		keyOffset		Starting Point of the Key
     * @param		length			Length of the Key to be Set
     * @param		character		Content to be Set
     *
     * @return		none
     ********************************************************************/
    public void setKey (int keyOffset, int length, byte character) {

        Arrays.fill (this.key, keyOffset, keyOffset + length, character);

    }

    public byte[] getValue () {

        return this.value;

    }

    /**************************************************************************
     * Description:	Set A Part of Value to "character"
     *
     * @param		valueOffset		Starting Point of the Value
     * @param		length			Length of the Value to be Set
     * @param		character		Content to be Set
     *
     * @return		none
     **************************************************************************/
    public void setValue (int valueOffset, int length, byte character) {

        Arrays.fill (this.value, valueOffset, valueOffset + length, character);

    }


    /**********************************************************************************************
     * Description:	Get An Element of Value with A Certain Index
     *
     * @param		index
     *
     * @return		The (index + 1)-th Element of Value
     **********************************************************************************************/
    public byte getValueElement (int index) {

        return this.value[index];

    }

    /************************************************************
     * Description:	Set An Element of Value with A Certain Index
     * 				to "character"
     *
     * @param		index
     * @param		character	Content to be Set
     *
     * @return		none
     ************************************************************/
    public void setValueElement (int index, byte character) {

        this.value[index] = character;

    }

}