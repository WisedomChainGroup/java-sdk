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
public class HashtimeblockGet  {
    @RLP(0)
    private byte[] transferhash;
    @RLP(1)
    private String origintext;

    public byte[] RLPserialization() {
        return RLPCodec.encode(HashtimeblockGet.builder()
                                .transferhash(this.getTransferhash())
                                .origintext(this.getOrigintext()));
    }

    public HashtimeblockGet RLPdeserialization(byte[] payload) {
        try {
            HashtimeblockGet hashtimeblockGet = RLPCodec.decode(payload,HashtimeblockGet.class);
            this.transferhash = hashtimeblockGet.getTransferhash();
            this.origintext = hashtimeblockGet.getOrigintext();
            return hashtimeblockGet;
        } catch (Exception e) {
            throw e;
        }
    }

}
