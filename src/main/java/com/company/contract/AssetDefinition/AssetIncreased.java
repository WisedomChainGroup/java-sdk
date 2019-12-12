package com.company.contract.AssetDefinition;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.tdf.rlp.RLP;
import org.tdf.rlp.RLPDeserializer;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AssetIncreased{
    @RLP(0)
    private long amount;

    public boolean RLPdeserialization(byte[] payload) {
        try{
            AssetIncreased assetIncreased = RLPDeserializer.deserialize(payload, AssetIncreased.class);
            this.amount= assetIncreased.amount;
        }catch (Exception e){
            return false;
        }
        return true;
    }

}
