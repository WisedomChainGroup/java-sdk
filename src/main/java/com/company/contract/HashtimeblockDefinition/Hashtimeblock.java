package com.company.contract.HashtimeblockDefinition;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.tdf.rlp.RLP;
import org.tdf.rlp.RLPCodec;
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Hashtimeblock {
    @RLP(0)
    private byte[] assetHash;
    @RLP(1)
    private byte[] pubkeyHash;


    public byte[] RLPserialization() {
        return RLPCodec.encode(Hashtimeblock.builder()
                                .assetHash(this.getAssetHash())
                                .pubkeyHash(this.getPubkeyHash()));
    }

    public Hashtimeblock RLPdeserialization(byte[] payload) {
        try {
            Hashtimeblock hashtimeblock = RLPCodec.decode(payload,Hashtimeblock.class);
            this.assetHash = hashtimeblock.getAssetHash();
            this.pubkeyHash = hashtimeblock.getPubkeyHash();
            return hashtimeblock;
        } catch (Exception e) {
            throw e;
        }
    }
}
