package com.company.contract.MultipleDefinition;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.tdf.rlp.RLP;
import org.tdf.rlp.RLPCodec;
import org.tdf.rlp.RLPElement;

import java.util.List;

@Data
@NoArgsConstructor
@Builder
public class Multiple{

    @RLP(0)
    private byte[] assetHash;
    @RLP(1)
    private int max;
    @RLP(2)
    private int min;
    @RLP(3)
    private List<byte[]> pubList;//公钥hash
    @RLP(4)
    private long amount;

    public Multiple RLPdeserialization(byte[] payload) {
        try{
            Multiple multiple= RLPCodec.decode(payload,Multiple.class);
            this.assetHash=multiple.getAssetHash();
            this.min=multiple.getMin();
            this.max=multiple.getMax();
            this.pubList=multiple.getPubList();
            this.amount=multiple.getAmount();
            return multiple;
        }catch (Exception e){
            throw e;
        }
    }
    public byte[] RLPdeserialization() {
        return RLPElement.readRLPTree(this).getEncoded();
    }

    public Multiple(byte[] assetHash, int min, int max, List<byte[]> pubList, long amount) {
        this.assetHash = assetHash;
        this.min = min;
        this.max = max;
        this.pubList = pubList;
        this.amount = amount;
    }
}
