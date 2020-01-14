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
public class AssetChangeowner {
    @RLP(0)
    private byte[] newowner;

    public AssetChangeowner RLPdeserialization(byte[] payload) {
        try {
            AssetChangeowner assetChangeowner = RLPCodec.decode(payload, AssetChangeowner.class);
            this.newowner = assetChangeowner.getNewowner();
            return assetChangeowner;
        } catch (Exception e) {
            throw e;
        }
    }

    public byte[] RLPdeserialization() {
        return RLPElement.readRLPTree(this).getEncoded();
    }

}
