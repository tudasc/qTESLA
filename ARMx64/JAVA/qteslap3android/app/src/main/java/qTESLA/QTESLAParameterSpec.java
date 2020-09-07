/*******************************************************************************
 * qTESLA: An Efficient Post-Quantum Signature Scheme Based on the R-LWE Problem
 *
 * Algorithm Parameters of qTESLA Specification for Heuristic or Provably Secure
 * Parameter Sets
 *
 * @author Yinhua Xu
 ********************************************************************************/

package qTESLA;

import java.security.spec.AlgorithmParameterSpec;

public final class QTESLAParameterSpec implements AlgorithmParameterSpec {

    /**
     * qTESLA Parameter Set
     */
    private String parameterSet;

    /*************************************************
     * qTESLA Parameter Specification Constructor
     *
     * @param parameterSet		qTESLA Parameter Set
     *************************************************/
    public QTESLAParameterSpec (String parameterSet) {

        this.parameterSet = parameterSet;

    }

    /*************************************
     * Getter of Parameter Set
     *
     * @return	none
     *************************************/
    public String getParameterSet () {

        return this.parameterSet;

    }

}