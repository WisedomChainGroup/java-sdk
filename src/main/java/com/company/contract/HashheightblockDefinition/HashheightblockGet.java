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
public class HashheightblockGet {
    @RLP(0)
    private byte[] transferhash;
    @RLP(1)
    private String origintext;

    public byte[] RLPserialization() {
        return RLPCodec.encode(HashheightblockGet.builder()
                                .transferhash(this.transferhash)
                                .origintext(this.origintext));
    }

    public HashheightblockGet RLPdeserialization(byte[] payload) {
        try {
            HashheightblockGet hashheightblockGet = RLPCodec.decode(payload,HashheightblockGet.class);
            this.transferhash = hashheightblockGet.transferhash;
            this.origintext = hashheightblockGet.origintext;
            return hashheightblockGet;
        }catch (Exception e){
            throw e;
        }


    }
}
