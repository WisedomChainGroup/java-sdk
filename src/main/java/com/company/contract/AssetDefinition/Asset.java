package com.company.contract.AssetDefinition;

import lombok.*;
import org.tdf.rlp.RLP;
import org.tdf.rlp.RLPElement;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class Asset {

    public enum AssetRule{
        changeowner,transfer,increased
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


    public byte[] RLPserialization() {
        return RLPElement.encode(new Asset(
                                        this.getCode(),
                                        this.getOffering(),
                                        this.getTotalamount(),
                                        this.getCreateuser(),
                                        this.getOwner(),
                                        this.getAllowincrease()
                                )).getEncoded();
    }
}
