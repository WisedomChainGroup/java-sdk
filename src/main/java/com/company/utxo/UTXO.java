package com.company.utxo;

public class UTXO {

    private byte txtype;
    private byte[] hash;
    private int index;
    private long amount;
    private long height;
    private boolean iscoinbase;
    private String address;
    private byte[] outscript;

    public UTXO(){

    }

    public UTXO(int index){
        this.index = index;
    }

    public byte getTxtype() {
        return txtype;
    }

    public void setTxtype(byte txtype) {
        this.txtype = txtype;
    }

    public byte[] getHash() {
        return hash;
    }

    public void setHash(byte[] hash) {
        this.hash = hash;
    }

    public int getIndex() {
        return index;
    }

    public void setIndex(int index) {
        this.index = index;
    }

    public long getAmount() {
        return amount;
    }

    public void setAmount(long amount) {
        this.amount = amount;
    }

    public long getHeight() {
        return height;
    }

    public void setHeight(long height) {
        this.height = height;
    }

    public boolean isIscoinbase() {
        return iscoinbase;
    }

    public void setIscoinbase(boolean iscoinbase) {
        this.iscoinbase = iscoinbase;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public byte[] getOutscript() {
        return outscript;
    }

    public void setOutscript(byte[] outscript) {
        this.outscript = outscript;
    }

}
