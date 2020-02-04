package com.company.contract.HashheightblockDefinition;

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
public class Hashheightblock {
    @RLP(0)
    private byte[] assetHash;
    @RLP(1)
    private byte[] pubkeyHash;


    public byte[] RLPserialization() {
        return RLPCodec.encode(Hashheightblock.builder()
                .assetHash(this.getAssetHash())
                .pubkeyHash(this.getPubkeyHash()));
    }

    public Hashheightblock RLPdeserialization(byte[] payload) {
        try {
            Hashheightblock hashheightblock = RLPCodec.decode(payload, Hashheightblock.class);
            this.assetHash = hashheightblock.getAssetHash();
            this.pubkeyHash = hashheightblock.getPubkeyHash();
            return hashheightblock;
        }catch (Exception e) {
            throw e;
        }
    }
}
