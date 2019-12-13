package com.company.contract.AssetDefinition;

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
public class AssetTransfer{
    @RLP(0)
    private byte[] from;
    @RLP(1)
    private byte[] to;
    @RLP(2)
    private long value;


    public boolean RLPdeserialization(byte[] payload) {
        try{
            AssetTransfer assetTransfer = RLPCodec.decode(payload, AssetTransfer.class);
            this.from= assetTransfer.getFrom();
            this.to= assetTransfer.getTo();
            this.value= assetTransfer.getValue();
        }catch (Exception e){
            return false;
        }
        return true;
    }

}
