package com.company.contract.AssetDefinition;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.tdf.rlp.RLP;
import org.tdf.rlp.RLPCodec;
import org.tdf.rlp.RLPElement;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AssetIncreased {
    @RLP(0)
    private long amount;

    public AssetIncreased RLPdeserialization(byte[] payload) {
        try {
            AssetIncreased assetIncreased = RLPCodec.decode(payload, AssetIncreased.class);
            this.amount = assetIncreased.amount;
            return assetIncreased;
        } catch (Exception e) {
            throw e;
        }
    }

    public byte[] RLPdeserialization() {
        return RLPElement.readRLPTree(this).getEncoded();
    }

}
