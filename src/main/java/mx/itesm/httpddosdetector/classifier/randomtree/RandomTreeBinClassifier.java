package mx.itesm.httpddosdetector.classifier.randomtree;

import mx.itesm.httpddosdetector.classifier.Classifier;
import mx.itesm.httpddosdetector.classifier.randomtree.codec.RandomTreeCodec;
import mx.itesm.httpddosdetector.flow.parser.FlowData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import weka.classifiers.trees.RandomTree;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;

import java.util.ArrayList;

public class RandomTreeBinClassifier extends Classifier {
    public enum Class {
        /**
         * Indicates if there was an error while classifying the flow
         */
        ERROR(-1),

        /**
         * Indicates if the flow is part of normal network traffic
         */
        NORMAL(0),

        /**
         * Indicates if the flow is part of a http ddos attack
         */
        ATTACK(1),

        /**
         * Indicates if the flow is part of a http ddos slowbody2 attack
         */
        SLOWBODY2(2),

        /**
         * Indicates if the flow is part of a http ddos slowread attack
         */
        SLOWREAD(3),

        /**
         * Indicates if the flow is part of a http ddos ddossim attack
         */
        DDOSSIM(4),

        /**
         * Indicates if the flow is part of a http ddos slowheaders attack
         */
        SLOWHEADERS(5),

        /**
         * Indicates if the flow is part of a http ddos goldeneye attack
         */
        GOLDENEYE(6),

        /**
         * Indicates if the flow is part of a http ddos rudy attack
         */
        RUDY(7),

        /**
         * Indicates if the flow is part of a http ddos hulk attack
         */
        HULK(8),

        /**
         * Indicates if the flow is part of a http ddos slowloris attack
         */
        SLOWLORIS(9);

        private final int value;

        private Class(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        public static Class valueOf(int value) {
            switch(value){
                case 0:
                    return RandomTreeBinClassifier.Class.NORMAL;
                case 1: 
                    return RandomTreeBinClassifier.Class.ATTACK;
                case 2:
                    return RandomTreeBinClassifier.Class.SLOWBODY2;
                case 3:
                    return RandomTreeBinClassifier.Class.SLOWREAD;
                case 4:
                    return RandomTreeBinClassifier.Class.DDOSSIM;
                case 5:
                    return RandomTreeBinClassifier.Class.SLOWHEADERS;
                case 6:
                    return RandomTreeBinClassifier.Class.GOLDENEYE;
                case 7:
                    return RandomTreeBinClassifier.Class.RUDY;
                case 8:
                    return RandomTreeBinClassifier.Class.HULK;
                case 9:
                    return RandomTreeBinClassifier.Class.SLOWLORIS;
                default:
                    return RandomTreeBinClassifier.Class.ERROR;
            }
        }
    }

    /**
     * Features indexes
     */
    static final int TOTAL_FPACKETS = 0;
    static final int TOTAL_FVOLUME = 1;
    static final int TOTAL_BPACKETS = 2;
    static final int TOTAL_BVOLUME = 3;
    static final int FPKTL = 4;
    static final int BPKTL = 5;
    static final int FIAT = 6;
    static final int BIAT = 7;
    static final int DURATION = 8;
    static final int ACTIVE = 9;
    static final int IDLE = 10;
    static final int SFLOW_FPACKETS = 11;
    static final int SFLOW_FBYTES = 12;
    static final int SFLOW_BPACKETS = 13;
    static final int SFLOW_BBYTES = 14;
    static final int FPSH_CNT = 15;
    static final int BPSH_CNT = 16;
    static final int FURG_CNT = 17;
    static final int BURG_CNT = 18;
    static final int TOTAL_FHLEN = 19;
    static final int TOTAL_BHLEN = 20;
    static final int NUM_FEATURES = 21;

    static final int MIN = 0;
    static final int MEAN = 1;
    static final int MAX = 2;
    static final int STD = 4;

    private static Logger log = LoggerFactory.getLogger(RandomTreeBinClassifier.class);

    private RandomTree tree;

    public void Load(String filepath) {
       RandomTreeCodec codec = new RandomTreeCodec();
       tree = codec.decode(filepath);
       super.Load(filepath);
    }

    /**
     * Classifies the flow
     *
     * @return int enumerator that determines the class of the FlowData parameter
     */
    public int Classify(FlowData f) {
        if (super.Classify(f) == -1) {
            return Class.ERROR.value;
        }

        log.debug("Building instance for classification.");
       Instance instance = buildInstance(f);

        try {
            log.debug("Calling classifyInstance()...");
           Double doubleClass = tree.classifyInstance(instance);
           Class classifiedAs = Class.valueOf(doubleClass.intValue());

           log.debug("Flow classified as " + classifiedAs);

           return classifiedAs.value;
        } catch(Exception e) {
            log.error("Error while trying to classify flow.");
            log.error(e.getMessage());
        }

        return Class.ERROR.value;
    }

   private Instance buildInstance(FlowData f) {
        /**
         * Create 40 empty attributes.
         */
       Attribute total_fpackets = new Attribute("total_fpackets");
       Attribute total_fvolume = new Attribute("total_fvolume");
       Attribute total_bpackets = new Attribute("total_bpackets");
       Attribute total_bvolume = new Attribute("total_bvolume");
       Attribute min_fpktl = new Attribute("min_fpktl");
       Attribute mean_fpktl = new Attribute("mean_fpktl");
       Attribute max_fpktl = new Attribute("max_fpktl");
       Attribute std_fpktl = new Attribute("std_fpktl");
       Attribute min_bpktl = new Attribute("min_bpktl");
       Attribute mean_bpktl = new Attribute("mean_bpktl");
       Attribute max_bpktl = new Attribute("max_bpktl");
       Attribute std_bpktl = new Attribute("std_bpktl");
       Attribute min_fiat = new Attribute("min_fiat");
       Attribute mean_fiat = new Attribute("mean_fiat");
       Attribute max_fiat = new Attribute("max_fiat");
       Attribute std_fiat = new Attribute("std_fiat");
       Attribute min_biat = new Attribute("min_biat");
       Attribute mean_biat = new Attribute("mean_biat");
       Attribute max_biat = new Attribute("max_biat");
       Attribute std_biat = new Attribute("std_biat");
       Attribute duration = new Attribute("duration");
       Attribute min_active = new Attribute("min_active");
       Attribute mean_active = new Attribute("mean_active");
       Attribute max_active = new Attribute("max_active");
       Attribute std_active = new Attribute("std_active");
       Attribute min_idle = new Attribute("min_idle");
       Attribute mean_idle = new Attribute("mean_idle");
       Attribute max_idle = new Attribute("max_idle");
       Attribute std_idle = new Attribute("std_idle");
       Attribute sflow_fpackets = new Attribute("sflow_fpackets");
       Attribute sflow_fbytes = new Attribute("sflow_fbytes");
       Attribute sflow_bpackets = new Attribute("sflow_bpackets");
       Attribute sflow_bbytes = new Attribute("sflow_bbytes");
       Attribute fpsh_cnt = new Attribute("fpsh_cnt");
       Attribute bpsh_cnt = new Attribute("bpsh_cnt");
       Attribute furg_cnt = new Attribute("furg_cnt");
       Attribute total_fhlen = new Attribute("total_fhlen");
       Attribute total_bhlen = new Attribute("total_bhlen");

        /**
         * Create empty instance that sets weight to one,
         * all values to be missing, and the reference to
         * the dataset to null.
         */
       Instance instance = new DenseInstance(40);

       instance.setValue(total_fpackets, f.f[TOTAL_FPACKETS].Get());
       instance.setValue(total_fvolume, f.f[TOTAL_FVOLUME].Get());
       instance.setValue(total_bpackets, f.f[TOTAL_BPACKETS].Get());
       instance.setValue(total_bpackets, f.f[TOTAL_BPACKETS].Get());
       instance.setValue(total_bvolume, f.f[TOTAL_BVOLUME].Get());

       ArrayList<Long> fpktlDistribution = f.f[FPKTL].ToArrayList();
       instance.setValue(min_fpktl, fpktlDistribution.get(MIN));
       instance.setValue(mean_fpktl, fpktlDistribution.get(MEAN));
       instance.setValue(max_fpktl, fpktlDistribution.get(MAX));
       instance.setValue(std_fpktl, fpktlDistribution.get(STD));

       ArrayList<Long> bpktl = f.f[BPKTL].ToArrayList();
       instance.setValue(min_bpktl, bpktl.get(MIN));
       instance.setValue(mean_bpktl, bpktl.get(MEAN));
       instance.setValue(max_bpktl, bpktl.get(MAX));
       instance.setValue(std_bpktl, bpktl.get(STD));

       ArrayList<Long> fiat = f.f[FIAT].ToArrayList();
       instance.setValue(min_fiat, fiat.get(MIN));
       instance.setValue(mean_fiat, fiat.get(MEAN));
       instance.setValue(max_fiat, fiat.get(MAX));
       instance.setValue(std_fiat, fiat.get(STD));

       ArrayList<Long> biat = f.f[FIAT].ToArrayList();
       instance.setValue(min_biat, biat.get(MIN));
       instance.setValue(mean_biat, biat.get(MEAN));
       instance.setValue(max_biat, biat.get(MAX));
       instance.setValue(std_biat, biat.get(STD));

       instance.setValue(duration, f.f[DURATION].Get());

       ArrayList<Long> active = f.f[ACTIVE].ToArrayList();
       instance.setValue(min_active, active.get(MIN));
       instance.setValue(mean_active, active.get(MEAN));
       instance.setValue(max_active, active.get(MAX));
       instance.setValue(std_active, active.get(STD));

       ArrayList<Long> idle = f.f[IDLE].ToArrayList();
       instance.setValue(min_idle, idle.get(MIN));
       instance.setValue(mean_idle, idle.get(MEAN));
       instance.setValue(max_idle, idle.get(MAX));
       instance.setValue(std_idle, idle.get(STD));

       instance.setValue(sflow_fpackets, f.f[SFLOW_FPACKETS].Get());
       instance.setValue(sflow_fbytes, f.f[SFLOW_FBYTES].Get());
       instance.setValue(sflow_bpackets, f.f[SFLOW_FPACKETS].Get());
       instance.setValue(sflow_bbytes, f.f[SFLOW_BBYTES].Get());
       instance.setValue(fpsh_cnt, f.f[FPSH_CNT].Get());
       instance.setValue(bpsh_cnt, f.f[BPSH_CNT].Get());
       instance.setValue(furg_cnt, f.f[FURG_CNT].Get());
       instance.setValue(total_fhlen, f.f[TOTAL_FHLEN].Get());
       instance.setValue(total_bhlen, f.f[TOTAL_BHLEN].Get());

       return instance;
    }
}
