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
@AllArgsConstructor
@Builder
public class Multiple{

    @RLP(0)
    private byte[] assetHash;
    @RLP(1)
    private int max;
    @RLP(2)
    private int min;
    @RLP(3)
    private List<byte[]> pubList;//公钥数组
    @RLP(4)
    private List<byte[]> signatures;//签名数组
    @RLP(5)
    private List<byte[]> pubkeyHashList;//公钥哈希数组

    public Multiple RLPdeserialization(byte[] payload) {
        try{
            Multiple multiple= RLPCodec.decode(payload,Multiple.class);
            this.assetHash=multiple.getAssetHash();
            this.max=multiple.getMax();
            this.min=multiple.getMin();
            this.pubList=multiple.getPubList();
            this.signatures=multiple.getSignatures();
            this.pubkeyHashList = multiple.getPubkeyHashList();
            return multiple;
        }catch (Exception e){
            throw e;
        }
    }
    public byte[] RLPdeserialization() {
        return RLPElement.readRLPTree(this).getEncoded();
    }

}
