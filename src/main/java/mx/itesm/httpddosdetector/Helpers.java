/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package mx.itesm.httpddosdetector;

import java.lang.Math;

/**
 * Helpers functions for the HTTP DDos Detector
 */
public class Helpers {

    // Calculates the standard deviation of a feature.
    static float stddev(float sqsum, float sum, long count) {
        if (count < 2) {
            return 0;
        }
        float n = (float) count;
        return (float) Math.sqrt((sqsum - (sum * sum / n)) / (n - 1));
    }

    // Returns the minimum of two longs
    static long min(long i1, long i2) {
        if (i1 < i2) {
            return i1;
        }
        return i2;
    }

    // Returns the minimum of two ints
    static int min(int i1, int i2) {
        if (i1 < i2) {
            return i1;
        }
        return i2;
    }

}