package com.company.contract.RateheightlockDefinition;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.tdf.common.util.ByteArrayMap;
import org.tdf.rlp.RLP;
import org.tdf.rlp.RLPCodec;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Rateheightlock{

    @RLP(0)
    private byte[] assetHash;
    @RLP(1)
    private long onetimedepositmultiple;
    @RLP(2)
    private int withdrawperiodheight;
    @RLP(3)
    private String withdrawrate;
    @RLP(4)
    private byte[] dest;
    @RLP(5)
    private Map<byte[],Extract> stateMap;

    public byte[] RLPserialization() {
//        return RLPElement.readRLPTree(this).getEncoded();
        return RLPCodec.encode(Rateheightlock.builder()
                .assetHash(this.assetHash)
                .onetimedepositmultiple(this.onetimedepositmultiple)
                .withdrawperiodheight(this.withdrawperiodheight)
                .withdrawrate(this.withdrawrate)
                .dest(this.dest)
                .stateMap(this.stateMap).build());
    }

    public Rateheightlock RLPdeserialization(byte[] payload) {
        try {
            Rateheightlock rateheightlock = RLPCodec.decode(payload, Rateheightlock.class);
            rateheightlock.assetHash = rateheightlock.getAssetHash();
            rateheightlock.onetimedepositmultiple = rateheightlock.getOnetimedepositmultiple();
            rateheightlock.withdrawperiodheight = rateheightlock.getWithdrawperiodheight();
            rateheightlock.withdrawrate = rateheightlock.getWithdrawrate();
            rateheightlock.dest = rateheightlock.getDest();
            rateheightlock.stateMap = new ByteArrayMap<>(rateheightlock.getStateMap());
            return rateheightlock;
        } catch (Exception e) {
            throw e;
        }
    }
}
