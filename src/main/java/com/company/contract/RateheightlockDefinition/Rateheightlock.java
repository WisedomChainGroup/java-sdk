package com.company.contract.RateheightlockDefinition;

import com.company.contract.AssetDefinition.Asset;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.tdf.common.util.ByteArrayMap;
import org.tdf.rlp.RLP;
import org.tdf.rlp.RLPCodec;
import org.tdf.rlp.RLPDecoding;
import org.tdf.rlp.RLPElement;

import java.math.BigDecimal;

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
    private BigDecimal withdrawrate;
    @RLP(4)
    private byte[] dest;
    @RLP(5)
    @RLPDecoding(as = ByteArrayMap.class)
    private ByteArrayMap<Extract> stateMap;

    public byte[] RLPserialization() {
        return RLPElement.readRLPTree(this).getEncoded();
    }

    public Rateheightlock RLPdeserialization(byte[] payload) {
        try {
            Rateheightlock rateheightlock = RLPCodec.decode(payload, Rateheightlock.class);
            this.assetHash = rateheightlock.getAssetHash();
            this.onetimedepositmultiple = rateheightlock.getOnetimedepositmultiple();
            this.withdrawperiodheight = rateheightlock.getWithdrawperiodheight();
            this.withdrawrate = rateheightlock.getWithdrawrate();
            this.dest = rateheightlock.getDest();
            this.stateMap = rateheightlock.getStateMap();
            return rateheightlock;
        } catch (Exception e) {
            throw e;
        }
    }
}
