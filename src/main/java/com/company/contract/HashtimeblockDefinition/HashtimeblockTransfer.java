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
public class HashtimeblockTransfer{
    @RLP(0)
    private Long value;
    @RLP(1)
    private byte[] hashresult;
    @RLP(2)
    private Long timestamp;

    public byte[] RLPserialization() {
        return RLPCodec.encode(HashtimeblockTransfer.builder()
                .value(this.getValue())
                .hashresult(this.getHashresult())
                .timestamp(this.getTimestamp()));
    }

    public HashtimeblockTransfer RLPdeserialization(byte[] payload) {
        try {
            HashtimeblockTransfer hashtimeblockTransfer = RLPCodec.decode(payload,HashtimeblockTransfer.class);
            this.value = hashtimeblockTransfer.getValue();
            this.hashresult = hashtimeblockTransfer.getHashresult();
            this.timestamp = hashtimeblockTransfer.getTimestamp();
            return hashtimeblockTransfer;
        } catch (Exception e) {
            throw e;
        }
    }
}
