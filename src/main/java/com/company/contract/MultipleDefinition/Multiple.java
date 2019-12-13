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
public class Multiple{

    @RLP(0)
    private byte[] assetHash;
    @RLP(1)
    private int min;
    @RLP(2)
    private int max;
    @RLP(3)
    private List<byte[]> pubList;//公钥hash
    @RLP(4)
    private long amount;

    public boolean RLPdeserialization(byte[] payload) {
        try{
            Multiple multiple= RLPCodec.decode(payload,Multiple.class);
            this.assetHash=multiple.getAssetHash();
            this.min=multiple.getMin();
            this.max=multiple.getMax();
            this.pubList=multiple.getPubList();
            this.amount=multiple.getAmount();
        }catch (Exception e){
            return false;
        }
        return true;
    }

}
