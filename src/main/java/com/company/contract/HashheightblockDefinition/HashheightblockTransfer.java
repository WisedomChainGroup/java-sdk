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
public class HashheightblockTransfer {
    @RLP(0)
    private Long value;
    @RLP(1)
    private byte[] hashresult;
    @RLP(2)
    private Long height;

    public byte[] RLPserialization() {
        return RLPCodec.encode(HashheightblockTransfer.builder()
                                .hashresult(this.hashresult)
                                .height(this.height)
                                .value(this.value));
    }

    public HashheightblockTransfer RLPdeserialization(byte[] payload) {
        try {
            HashheightblockTransfer hashheightblockTransfer = RLPCodec.decode(payload,HashheightblockTransfer.class);
            this.value = hashheightblockTransfer.value;
            this.hashresult = hashheightblockTransfer.hashresult;
            this.height = hashheightblockTransfer.height;
            return hashheightblockTransfer;
        }catch (Exception e){
            throw e;
        }

    }
}
