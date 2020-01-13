package com.company.contract.AssetDefinition;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.tdf.rlp.RLP;
import org.tdf.rlp.RLPCodec;
import org.tdf.rlp.RLPElement;

@Data
@NoArgsConstructor
@Builder
public class AssetTransfer {
    @RLP(0)
    private byte[] from;
    @RLP(1)
    private byte[] to;
    @RLP(2)
    private long value;


    public AssetTransfer RLPdeserialization(byte[] payload) {
        try {
            AssetTransfer assetTransfer = RLPCodec.decode(payload, AssetTransfer.class);
            this.from = assetTransfer.getFrom();
            this.to = assetTransfer.getTo();
            this.value = assetTransfer.getValue();
            return assetTransfer;
        } catch (Exception e) {
            throw e;
        }
    }

    public byte[] RLPdeserialization() {
        return RLPElement.readRLPTree(this).getEncoded();
    }

    public AssetTransfer(byte[] from, byte[] to, long value) {
        this.from = from;
        this.to = to;
        this.value = value;
    }
}
