package com.company.contract.AssetDefinition;

import lombok.*;
import org.tdf.rlp.RLP;
import org.tdf.rlp.RLPCodec;
import org.tdf.rlp.RLPElement;

@Data
@NoArgsConstructor
public class Asset {

    public enum AssetRule {
        changeowner, transfer, increased
    }

    @RLP(0)
    private String code;
    @RLP(1)
    private long offering;
    @RLP(2)
    private long totalamount;
    @RLP(3)
    private byte[] createuser;
    @RLP(4)
    private byte[] owner;
    @RLP(5)
    private int allowincrease;
    @RLP(6)
    private byte[] info;


    public byte[] RLPserialization() {
        return RLPElement.readRLPTree(this).getEncoded();
    }

    public Asset RLPdeserialization(byte[] payload) {
        try {
            Asset asset = RLPCodec.decode(payload, Asset.class);
            this.code = asset.getCode();
            this.offering = asset.getOffering();
            this.totalamount = asset.getTotalamount();
            this.createuser = asset.getCreateuser();
            this.owner = asset.getOwner();
            this.allowincrease = asset.getAllowincrease();
            this.info = asset.getInfo();
            return asset;
        } catch (Exception e) {
            throw e;
        }
    }

    public Asset(String code, long offering, long totalamount, byte[] createuser, byte[] owner, int allowincrease,byte[] info) {
        this.code = code;
        this.offering = offering;
        this.totalamount = totalamount;
        this.createuser = createuser;
        this.owner = owner;
        this.allowincrease = allowincrease;
        this.info = info;
    }

}
