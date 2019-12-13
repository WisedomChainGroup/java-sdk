package com.company.contract.MultipleDefinition;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.tdf.rlp.RLP;
import org.tdf.rlp.RLPCodec;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MultTransfer{
    @RLP(0)
    private int origin;//0是普通账户地址，1是多签地址
    @RLP(1)
    private int dest;
    @RLP(2)
    private byte[] pubhash;
    @RLP(3)
    private List<byte[]> signaturesList;
    @RLP(4)
    private byte[] to;
    @RLP(5)
    private long value;

    public boolean RLPdeserialization(byte[] payload) {
        try{
            MultTransfer multTransfer= RLPCodec.decode(payload,MultTransfer.class);
            this.origin=multTransfer.getOrigin();
            this.dest=multTransfer.getDest();
            this.pubhash=multTransfer.getPubhash();
            this.signaturesList=multTransfer.getSignaturesList();
            this.to=multTransfer.getTo();
            this.value=multTransfer.getValue();
        }catch (Exception e){
            return false;
        }
        return false;
    }
}
