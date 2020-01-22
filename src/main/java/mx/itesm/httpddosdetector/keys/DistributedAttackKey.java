package mx.itesm.httpddosdetector.keys;

public class DistributedAttackKey {
    public Integer dstip; 
    public Integer dstport;
 
    public DistributedAttackKey(Integer dstip, Integer dstport) {
       this.dstip = dstip;
       this.dstport = dstport;
    }
 
    @Override   
    public boolean equals(Object obj) {
        if (!(obj instanceof DistributedAttackKey))
            return false;
        DistributedAttackKey ref = (DistributedAttackKey) obj;
        // We ignore the srcip since we are considering distributed attacks the sources could be different
        // but the destination port and ip should stay fixed
        return this.dstip.equals(ref.dstip) &&
            this.dstport.equals(ref.dstport);
    }
 
    @Override
    public int hashCode() {
        // We ignore the srcip since we are considering distributed attacks the sources could be different
        // but the destination port and ip should stay fixed
        return dstip.hashCode() ^ dstport.hashCode();
    }
 
 }