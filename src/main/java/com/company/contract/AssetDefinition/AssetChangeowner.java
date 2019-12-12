package com.company.contract.AssetDefinition;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.tdf.rlp.RLP;
import org.tdf.rlp.RLPDeserializer;


import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AssetChangeowner{
    @RLP(0)
    private byte[] newowner;

    public boolean RLPdeserialization(byte[] payload) {
        try{
            AssetChangeowner assetChangeowner = RLPDeserializer.deserialize(payload, AssetChangeowner.class);
            this.newowner= assetChangeowner.getNewowner();
        }catch (Exception e){
            return false;
        }
        return true;
    }
}
