/******************************************************************************
* qTESLA: An Efficient Post-Quantum Signature Scheme Based on the R-LWE Problem
*
* Number Theoretic Transform, Modular Reduction and Polynomial Functions
* 
* @author Yinhua Xu
*******************************************************************************/

package sctudarmstadt.qtesla.java;

import java.util.Arrays;

public class Polynomial {
	
	private static QTESLAParameter parameter;
	
	/*******************************************************
	 * Constructor of Manipulation in Polynomials
	 * 
	 * @param parameterSet		qTESLA Parameter Set
	 *******************************************************/
	public Polynomial (String parameterSet) {
		
		parameter = new QTESLAParameter (parameterSet);
		
	}
	
	/*********************************************
	 * Getter of qTESLA Parameter Object
	 * 
	 * @return	none
	 *********************************************/
	public QTESLAParameter getQTESLAParameter () {
		
		return parameter;
		
	}
	
	/***********************************************************************************************
	 * Description:	Peter Lawrence Montgomery Reduction for Heuristic qTESLA
	 * 
	 * @param		number				Number to be Reduced
	 * 
	 * @return		Reduced Number
	 ***********************************************************************************************/
	private int peterLawrenceMontgomeryReduction_MB (long a) {
		long u;
		
		u = (a * parameter.qInverse) & 0xFFFFFFFFL;
		u *= parameter.q;
		a += u;
		
		return (int)(a >> 32);		
	}
	
	private int peterLawrenceMontgomeryReduction (long number) {
		
		return (int) ((number + ((number * parameter.qInverse) & 0xFFFFFFFFL) * parameter.q) >> 32);
		
	}
	
	/***************************************************************************************
	 * Description:	Peter Lawrence Montgomery Reduction for Provably-Secure qTESLA
	 * 
	 * @param		number				Number to be Reduced
	 * 
	 * @return		Reduced Number
	 ***************************************************************************************/
	private long peterLawrenceMontgomeryReductionP (long number) {
		//System.out.println("");
		//System.out.println("");
		//System.out.println(number);
		
		long u = (number * parameter.qInverse) & 0xFFFFFFFFL;		
		u *= parameter.q;
		number += u;
		int tmp = (int)(number>>32);
		return tmp;
		//return (number + ((number * parameter.qInverse) & 0xFFFFFFFFL) * parameter.q) >> 32;
		
	}
	
	/***************************************************************************************************************************
	 * Description:	Paul Barrett Reduction for Heuristic Security Category 3 (Option for Size and Speed)
	 * 
	 * @param		number					Number to be Reduced
	 * 
	 * @return		Reduced Number
	 ***************************************************************************************************************************/
	public long paulBarrettReduction_MB (long a) {
		long u = ((long)a * parameter.paulBarrettMultiplier) >> parameter.paulBarrettDivisor;
		long tempi = a - (long)u * parameter.q;
		return a - (long)u * parameter.q;

	}
	
	public int paulBarrettReduction (int number) {
		
		return number - (int) (((long) number * parameter.paulBarrettMultiplier) >> parameter.paulBarrettDivisor) * parameter.q;
	
	}
	
	/**************************************************************************************************************
	 * Description:	Paul Barrett Reduction for Provably Secure qTESLA
	 * 
	 * @param		number					Number to be Reduced
	 * 
	 * @return		Reduced Number
	 **************************************************************************************************************/
	public long paulBarrettReduction (long number) {
		
		return number - ((number * parameter.paulBarrettMultiplier) >> parameter.paulBarrettDivisor) * parameter.q;
	
	}
	
	
	private void numberTheoreticTransform_MB (int a[], final int source[]) {		
		
		int numberOfProblem = parameter.n >> 1;
		int jTwiddle = 0;		
		for (; numberOfProblem > 0; numberOfProblem >>= 1) {
			int j = 0;
			
			for (int jFirst = 0; jFirst < parameter.n; jFirst = j + numberOfProblem) {
				long omega = (long)source[jTwiddle++];
				
				for (j = jFirst; j < jFirst + numberOfProblem; j++) {
					int temp = peterLawrenceMontgomeryReduction_MB((long)omega * a[j + numberOfProblem]);
					
			        a[j + numberOfProblem] = (int)paulBarrettReduction(a[j] - temp);
			        a[j] = (int)paulBarrettReduction(temp + a[j]);
					
				}
			}
		}			
		
		return;
	}
	
	/**********************************************************************************************************
	 * Description:	Forward Number Theoretic Transform for Heuristic qTESLA
	 *
	 * @param		destination		Destination of Transformation
	 * @param		source			Source of Transformation
	 * 
	 * @return		none
	 **********************************************************************************************************/
	private void numberTheoreticTransform (int destination[], final int source[]) {
		
		int numberOfProblem = parameter.n >> 1;
		int jTwiddle = 0;
		
		for (; numberOfProblem > 0; numberOfProblem >>= 1) {

			int j = 0;
			
			for (int jFirst = 0; jFirst < parameter.n; jFirst = j + numberOfProblem) {
				
				long omega = (long) source[jTwiddle++];
				
				for (j = jFirst; j < jFirst + numberOfProblem; j++) {
					
					int temporary = peterLawrenceMontgomeryReduction (omega * destination[j + numberOfProblem]);
					
					destination[j + numberOfProblem] = destination[j] - temporary;
					destination[j] = destination[j] + temporary;
					
				}
				
			}
		
		}
		
	}
	
	/****************************************************************************************************************
	 * Description:	Forward Number Theoretic Transform for Provably Secure qTESLA
	 * 
	 * @param		destination		Destination of Transformation
	 * @param		source			Source of Transformation
	 * 
	 * @return		none
	 ****************************************************************************************************************/
	private void numberTheoreticTransform (long destination[], final long source[]) {
		
		int numberOfProblem = parameter.n >> 1;
		int jTwiddle = 0;
//		int cnt = 0;
		
		for (; numberOfProblem > 0; numberOfProblem >>= 1) {
			
			int j = 0;
			
			if (parameter.parameterSet == "qTESLA-P-I") {
			
				for (int jFirst = 0; jFirst < parameter.n; jFirst = j + numberOfProblem) {
				
					long omega = source[jTwiddle++];
				
					for (j = jFirst; j < jFirst + numberOfProblem; j++) {
				
						long temporary = peterLawrenceMontgomeryReductionP (omega * destination[j + numberOfProblem]);
					
						destination[j + numberOfProblem] = destination[j] + (parameter.q - temporary);
						destination[j] = destination[j] + temporary;
				
					}
				
				}
			
			}
			
			if (parameter.parameterSet == "qTESLA-P-III") {	
				
				for (int jFirst = 0; jFirst < parameter.n; jFirst = j + numberOfProblem) {
					
					long omega = source[jTwiddle++];
					
					for (j = jFirst; j < jFirst + numberOfProblem; j++) {
						int temp = peterLawrenceMontgomeryReduction (omega * destination[j + numberOfProblem]);
									
						
						destination[j + numberOfProblem] = paulBarrettReduction (
							
							destination[j] + (2L * parameter.q - temp)
							
						);					
						
						destination[j] = paulBarrettReduction (destination[j] + temp);
						
					}
					
				}
				
			}
			
		}		
	}
		
	/*********************************************************************************************************
	 * Description:	Inverse Number Theoretic Transform for Heuristic qTESLA
	 * 
	 * @param		destination			Destination of Inverse Transformation
	 * @param		source				Source of Inverse Transformation
	 * 
	 * @return		none
	 *********************************************************************************************************/
	private void inverseNumberTheoreticTransform (int destination[], final int source[]) {
		
		int jTwiddle = 0;
		
		for (int numberOfProblem = 1; numberOfProblem < parameter.n; numberOfProblem *= 2) {
			
			int j = 0;
			
			for (int jFirst = 0; jFirst < parameter.n; jFirst = j + numberOfProblem) {
				
				long omega = (long) source[jTwiddle++];
				
				for (j = jFirst; j < jFirst + numberOfProblem; j++) {
					
					int temporary = destination[j];
					
					if (parameter.parameterSet == "qTESLA-I") {
					
						destination[j] = temporary + destination[j + numberOfProblem];
					
					}
					
					if (
							parameter.parameterSet == "qTESLA-III-Speed" ||
							parameter.parameterSet == "qTESLA-III-Size"
							
					) {
						
						if (numberOfProblem == 16) {
							
							destination[j] = paulBarrettReduction (temporary + destination[j + numberOfProblem]);
							
						} else {
							
							destination[j] = temporary + destination[j + numberOfProblem];
							
						}
						
					}
					
					destination[j + numberOfProblem] = peterLawrenceMontgomeryReduction (
						
						omega * (temporary - destination[j + numberOfProblem])
						
					);
					
				}
				
			}
			
		}
		
		for (int i = 0; i < parameter.n / 2; i++) {
			
			destination[i] = peterLawrenceMontgomeryReduction ((long) parameter.r * destination[i]);
			
		}
		
	}
	
	/*********************************************************************************************************************
	 * Description:	Inverse Number Theoretic Transform for Provably Secure qTESLA
	 * 
	 * @param		destination			Destination of Inverse Transformation
	 * @param		destinationOffset	Starting Point of the Destination
	 * @param		source				Source of Inverse Transformation
	 * @param		sourceOffset		Starting Point of the Source
	 * 
	 * @return		none
	 *********************************************************************************************************************/
	private void inverseNumberTheoreticTransform_MB (
			
			int a[], int destinationOffset, final int w[], int sourceOffset
			
		) {
			
			int jTwiddle = 0;
			
			for (int numberOfProblem = 1; numberOfProblem < parameter.n; numberOfProblem *= 2) {
				int j = 0;	
				
				for (int jFirst = 0; jFirst < parameter.n; jFirst = j + numberOfProblem) {
					long omega = (long)w[sourceOffset + (jTwiddle++)];
					
					for (j = jFirst; j < jFirst + numberOfProblem; j++) {
						int temp = a[destinationOffset + j];
						
						a[destinationOffset + j] = 
								(int)paulBarrettReduction_MB(temp + a [destinationOffset + j + numberOfProblem] );
						a[destinationOffset + j + numberOfProblem] = 
								peterLawrenceMontgomeryReduction_MB((long)omega * (temp - a[destinationOffset + j+ numberOfProblem]));
					}
				}
				
			}				
		}
	
	private void inverseNumberTheoreticTransform (
			
		long destination[], int destinationOffset, final long source[], int sourceOffset
		
	) {
		
		int jTwiddle = 0;
		
		for (int numberOfProblem = 1; numberOfProblem < parameter.n; numberOfProblem *= 2) {
			
			int j = 0;
			
			if (parameter.parameterSet == "qTESLA-P-I") {
			
				for (int jFirst = 0; jFirst < parameter.n; jFirst = j + numberOfProblem) {
				
					long omega = source[sourceOffset + (jTwiddle++)];
				
					for (j = jFirst; j < jFirst + numberOfProblem; j++) {
					
						long temporary = destination[destinationOffset + j];
					
						destination[destinationOffset + j] =
								
							temporary + destination[destinationOffset + j + numberOfProblem];
					
						destination[destinationOffset + j + numberOfProblem] = (int)peterLawrenceMontgomeryReductionP (
								
							omega * (temporary + (2 * parameter.q - destination[destinationOffset + j + numberOfProblem]))
							
						);
					
					}
				
				}
			
				numberOfProblem *= 2;
			
				for (int jFirst = 0; jFirst < parameter.n; jFirst = j + numberOfProblem) {
				
					long omega = source[sourceOffset + (jTwiddle++)];
				
					for (j = jFirst; j < jFirst + numberOfProblem; j++) {
					
						long temporary = destination[destinationOffset + j];
					
						destination[destinationOffset + j] = paulBarrettReduction (
								
							temporary + destination[destinationOffset + j + numberOfProblem]
						
						);
					
						destination[destinationOffset + j + numberOfProblem] = (int)peterLawrenceMontgomeryReductionP (
							
							omega * (temporary + (2 * parameter.q - destination[destinationOffset + j + numberOfProblem]))
							
						);
					
					}
				
				}
			
			}
			
			if (parameter.parameterSet == "qTESLA-P-III") {
				
				for (int jFirst = 0; jFirst < parameter.n; jFirst = j + numberOfProblem) {
					
					long omega = source[sourceOffset + (jTwiddle++)];
					
					for (j = jFirst; j < jFirst + numberOfProblem; j++) {
						
						long temporary = destination[destinationOffset + j];
						
						destination[destinationOffset + j] = paulBarrettReduction (
								
							temporary + destination[destinationOffset + j + numberOfProblem]
									
						);
						
						destination[destinationOffset + j + numberOfProblem] = (int)paulBarrettReduction (
								
							peterLawrenceMontgomeryReductionP (
									
								omega * (temporary + (2L * parameter.q - destination[destinationOffset + j + numberOfProblem]))
								
							)
								
						);
					
					}
					
				}
				
			}
			
		}
		
	}
	
	/*********************************************************************************************************************
	 * Description:	Component Wise Polynomial Multiplication for Heuristic qTESLA
	 * 
	 * @param		product					Product = Multiplicand (*) Multiplier
	 * @param		multiplicand			Multiplicand Array
	 * @param		multiplier				Multiplier Array
	 * 
	 * @return		none
	 *********************************************************************************************************************/
	private void componentWisePolynomialMultiplication (int[] product, final int[] multiplicand, final int[] multiplier) {

		for (int i = 0; i < parameter.n; i++) {
			
			product[i] = peterLawrenceMontgomeryReduction ((long) multiplicand[i] * multiplier[i]);
			
		}
	
	}
	
	/**********************************************************************************
	 * Description:	Component Wise Polynomial Multiplication for Provably Secure qTESLA
	 * 
	 * @param		product					Product = Multiplicand (*) Multiplier
	 * @param		productOffset			Starting Point of the Product Array
	 * @param		multiplicand			Multiplicand Array
	 * @param		multiplicandOffset		Starting Point of the Multiplicand Array
	 * @param		multiplier				Multiplier Array
	 * @param		multiplierOffset		Starting Point of the Multiplier Array
	 * 
	 * @return		none
	 ***********************************************************************************/
	private void componentWisePolynomialMultiplication_MB (
			
			int[] product, int productOffset,
			final int[] multiplicand, int multiplicandOffset,
			final int[] multiplier, int multiplierOffset
			
		) {

			for (int i = 0; i < parameter.n; i++) {
				
				product[productOffset + i] = (int)peterLawrenceMontgomeryReduction_MB (
					
					(long)multiplicand[multiplicandOffset + i] * multiplier[multiplierOffset + i]
				
				);
				
			}
		
		}
	
	private void componentWisePolynomialMultiplication (
			
		long[] product, int productOffset,
		final long[] multiplicand, int multiplicandOffset,
		final long[] multiplier, int multiplierOffset
		
	) {

		for (int i = 0; i < parameter.n; i++) {
			
			product[productOffset + i] = (int)peterLawrenceMontgomeryReductionP (
				
				multiplicand[multiplicandOffset + i] * multiplier[multiplierOffset + i]
			
			);
			
		}
	
	}
	
	/**********************************************************************************************************
	 * Description:	Polynomial Number Theoretic Transform for Provably Secure qTESLA
	 * 
	 * @param		arrayNumberTheoreticTransform		Transformed Array
	 * @param		array								Array to be Transformed
	 * 
	 * @return		none
	 **********************************************************************************************************/
	public void polynomialNumberTheoreticTransform_MB (int[] a, final int[] array) {
		
		for (int i = 0; i < parameter.n; i++) {			
			a[i] = array[i];			
		}
		numberTheoreticTransform_MB (a, PolynomialProvablySecurei.ZETA_P_IIIi);		
	}
	
	
	public void polynomialNumberTheoreticTransform (long[] arrayNumberTheoreticTransform, final long[] array) {
		
		for (int i = 0; i < parameter.n; i++) {
			
			arrayNumberTheoreticTransform[i] = array[i];
			
		}
		
		if (parameter.parameterSet == "qTESLA-P-I") {
			
			numberTheoreticTransform (arrayNumberTheoreticTransform, PolynomialProvablySecure.ZETA_P_I);
			
		}
		
		if (parameter.parameterSet == "qTESLA-P-III") {
		
			numberTheoreticTransform (arrayNumberTheoreticTransform, PolynomialProvablySecure.ZETA_P_III);
		
		}
		
	}
	
	/*******************************************************************************************************
	 * Description:	Polynomial Multiplication for Heuristic qTESLA
	 * 
	 * @param		product					Product = Multiplicand * Multiplier
	 * @param		multiplicand			Multiplicand Array
	 * @param		multiplier				Multiplier Array
	 * 
	 * @return		none
	 *******************************************************************************************************/
	public void polynomialMultiplication (int[] product, final int[] multiplicand, final int[] multiplier) {
		
		int[] multiplierNumberTheoreticTransform = new int[parameter.n];
		
		for (int i = 0; i < parameter.n; i++) {
			
			multiplierNumberTheoreticTransform[i] = multiplier[i];
			
		}
		
		if (parameter.parameterSet == "qTESLA-I") {
			
			numberTheoreticTransform (multiplierNumberTheoreticTransform, PolynomialHeuristic.ZETA_I);
			componentWisePolynomialMultiplication (product, multiplicand, multiplierNumberTheoreticTransform);
			inverseNumberTheoreticTransform (product, PolynomialHeuristic.ZETA_INVERSE_I);
			
		}
		
		if (parameter.parameterSet == "qTESLA-III-Speed") {
		
			numberTheoreticTransform (multiplierNumberTheoreticTransform, PolynomialHeuristic.ZETA_III_SPEED);
			componentWisePolynomialMultiplication (product, multiplicand, multiplierNumberTheoreticTransform);
			inverseNumberTheoreticTransform (product, PolynomialHeuristic.ZETA_INVERSE_III_SPEED);
			
		}
		
		if (parameter.parameterSet == "qTESLA-III-Size") {
			
			numberTheoreticTransform (multiplierNumberTheoreticTransform, PolynomialHeuristic.ZETA_III_SIZE);
			componentWisePolynomialMultiplication (product, multiplicand, multiplierNumberTheoreticTransform);
			inverseNumberTheoreticTransform (product, PolynomialHeuristic.ZETA_INVERSE_III_SIZE);
			
		}
		
	}
	
	/*************************************************************************************************************
	 * Description:	Polynomial Multiplication for Provably Secure qTESLA Security
	 * 
	 * @param		product					Product = Multiplicand * Multiplier
	 * @param		productOffset			Starting Point of the Product Array
	 * @param		multiplicand			Multiplicand Array
	 * @param		multiplicandOffset		Starting Point of the Multiplicand Array
	 * @param		multiplier				Multiplier Array
	 * @param		multiplierOffset		Starting Point of the Multiplier Array
	 * 
	 * @return		none
	 *************************************************************************************************************/
	public void polynomialMultiplication_MB (
			
			int[] product, int productOffset,
			final int[] multiplicand, int multiplicandOffset,
			final int[] multiplier, int multiplierOffset
		
		) {
			
			componentWisePolynomialMultiplication_MB (
				
				product, productOffset, multiplicand, multiplicandOffset, multiplier, multiplierOffset
			
			);
			
			inverseNumberTheoreticTransform_MB (product, productOffset, PolynomialProvablySecurei.ZETA_INVERSE_P_IIIi, 0);			
		}
	
	
	public void polynomialMultiplication (
			
		long[] product, int productOffset,
		final long[] multiplicand, int multiplicandOffset,
		final long[] multiplier, int multiplierOffset
	
	) {
		
		componentWisePolynomialMultiplication (
			
			product, productOffset, multiplicand, multiplicandOffset, multiplier, multiplierOffset
		
		);
		
		if (parameter.parameterSet == "qTESLA-P-I") {
			
			inverseNumberTheoreticTransform (product, productOffset, PolynomialProvablySecure.ZETA_INVERSE_P_I, 0);
			
		}
		
		if (parameter.parameterSet == "qTESLA-P-III") {
			
			inverseNumberTheoreticTransform (product, productOffset, PolynomialProvablySecure.ZETA_INVERSE_P_III, 0);
			
		}
		
	}
	
	/*****************************************************************************************
	 * Description:	Polynomial Addition for Heuristic qTESLA
	 * 				Q + L_E < 2 ^ (CEIL (LOGARITHM (Q, 2)))
	 * 				No Necessary Reduction for Y + SC
	 * 
	 * @param		summation			Summation = Augend + Addend
	 * @param		augend				Augend Array
	 * @param		addend				Addend Array
	 * 
	 * @return		none
	 *****************************************************************************************/
	public void polynomialAddition (int[] summation, final int[] augend, final int[] addend) {
		
		for (int i = 0; i < parameter.n; i++) {
			
			summation[i] = augend[i] + addend[i];
			
		}
		
	}
	
	/*******************************************************************************************
	 * Description:	Polynomial Addition for Provably Secure qTESLA
	 * 				Q + L_E < 2 ^ (CEIL (LOGARITHM (Q, 2)))
	 * 				No Necessary Reduction for Y + SC
	 * 
	 * @param		summation			Summation = Augend + Addend
	 * @param		summationOffset		Starting Point of the Summation Array
	 * @param		augend				Augend Array
	 * @param		augendOffset		Starting Point of the Augend Array
	 * @param		addend				Addend Array
	 * @param		addendOffset		Starting Point of the Addend Array
	 * 
	 * @return		none
	 *******************************************************************************************/
	public void polynomialAddition_MB (
			
			int[] summation, int summationOffset,
			final int[] augend, int augendOffset,
			final int[] addend, int addendOffset
		
		) {
			
			for (int i = 0; i < parameter.n; i++) {
				
				summation[summationOffset + i] = augend[augendOffset + i] + addend[addendOffset + i];
				
			}
			
		}
	
	public void polynomialAddition (
			
		long[] summation, int summationOffset,
		final long[] augend, int augendOffset,
		final long[] addend, int addendOffset
	
	) {
		
		for (int i = 0; i < parameter.n; i++) {
			
			summation[summationOffset + i] = augend[augendOffset + i] + addend[addendOffset + i];
			
		}
		
	}
	
	/***************************************************************************************************
	 * Description:	Polynomial Addition with Correction for Heuristic qTESLA
	 * 				(Option for Size or Speed)
	 * 				Q + L_E < 2 ^ (CEIL (LOGARITHM (Q, 2)))
	 * 				No Necessary Reduction for Y + SC
	 * 
	 * @param		summation			Summation = Augend + Addend
	 * @param		augend				Augend Array
	 * @param		addend				Addend Array
	 * 
	 * @return		none
	 ***************************************************************************************************/
	public void polynomialAdditionCorrection (int[] summation, final int[] augend, final int[] addend) {
		
		for (int i = 0; i < parameter.n; i++) {
			
			summation[i]  = augend[i] + addend[i];
			/* If summation[i] < 0 Then Add Q */
			summation[i] += (summation[i] >> 31) & parameter.q;
			summation[i] -= parameter.q;
			/* If summation[i] >= Q Then Subtract Q */
			summation[i] += (summation[i] >> 31) & parameter.q;
			
		}
		
	}
	
	/********************************************************************************************
	 * Description:	Polynomial Addition with Correction for Provably Secure qTESLA
	 * 				Q + L_E < 2 ^ (CEIL (LOGARITHM (Q, 2)))
	 * 				No Necessary Reduction for Y + SC
	 * 
	 * @param		summation			Summation = Augend + Addend
	 * @param		summationOffset		Starting Point of the Summation
	 * @param		augend				Augend Array
	 * @param		augendOffset		Starting Point of the Augend
	 * @param		addend				Addend Array
	 * @param		addendOffset		Starting Point of the Addend
	 * 
	 * @return		none
	 ********************************************************************************************/
	public void polynomialAdditionCorrection_MB (			
			int[] summation, int summationOffset,
			final int[] augend, int augendOffset,
			final int[] addend, int addendOffset			
		) {			
			for (int i = 0; i < parameter.n; i++) {				
				summation[summationOffset + i]  = augend[addendOffset + i] + addend[addendOffset + i];
				/* If summation[i] < 0 Then Add Q */
				summation[summationOffset + i] += (summation[summationOffset + i] >> 31) & parameter.q;
				summation[summationOffset + i] -= parameter.q;
				/* If summation[i] >= Q Then Subtract Q */
				summation[summationOffset + i] += (summation[summationOffset + i] >> 31) & parameter.q;				
			}			
		}	
	
	public void polynomialAdditionCorrection (
			
		long[] summation, int summationOffset,
		final long[] augend, int augendOffset,
		final long[] addend, int addendOffset
		
	) {
		
		for (int i = 0; i < parameter.n; i++) {
			
			summation[summationOffset + i]  = augend[addendOffset + i] + addend[addendOffset + i];
			/* If summation[i] < 0 Then Add Q */
			summation[summationOffset + i] += (summation[summationOffset + i] >> 31) & parameter.q;
			summation[summationOffset + i] -= parameter.q;
			/* If summation[i] >= Q Then Subtract Q */
			summation[summationOffset + i] += (summation[summationOffset + i] >> 31) & parameter.q;
			
		}
		
	}
	
	/***********************************************************************************************************
	 * Description:	Polynomial Subtraction with Correction for Heuristic qTESLA
	 * 
	 * @param		difference					Difference = Minuend (-) Subtrahend
	 * @param		minuend						Minuend Array
	 * @param		subtrahend					Subtrahend Array
	 * 
	 * @return		none
	 ************************************************************************************************************/
	public void polynomialSubtractionCorrection (int[] difference, final int[] minuend, final int[] subtrahend) {
		
		for (int i = 0; i < parameter.n; i++) {
			
			difference[i]  = minuend[i] - subtrahend[i];
			/* If difference[i] < 0 Then Add Q */
			difference[i] += (difference[i] >> 31) & parameter.q;
			
		}
		
	}
	
	/***********************************************************************************************************
	 * Description:	Polynomial Subtraction with Peter Lawrence Montgomery Reduction for Heuristic qTESLA
	 * 
	 * @param		difference					Difference = Minuend (-) Subtrahend
	 * @param		minuend						Minuend Array
	 * @param		subtrahend					Subtrahend Array
	 * 
	 * @return		none
	 ***********************************************************************************************************/
	public void polynomialSubtractionReduction (int[] difference, final int[] minuend, final int[] subtrahend) {
		
		for (int i = 0; i < parameter.n; i++) {
			
			difference[i] = peterLawrenceMontgomeryReduction ((long) parameter.r * (minuend[i] - subtrahend[i]));
			
		}
		
	}
	
	/*********************************************************************************
	 * Description:	Polynomial Subtraction for Provably Secure qTESLA
	 * 
	 * @param		difference					Difference = Minuend (-) Subtrahend
	 * @param		differenceOffset			Starting Point of the Difference Array
	 * @param		minuend						Minuend Array
	 * @param		minuendOffset				Starting Point of the Minuend Array
	 * @param		subtrahend					Subtrahend Array
	 * @param		subtrahendOffset			Starting Point of the Subtrahend Array
	 * 
	 * @return		none
	 *********************************************************************************/
	public void polynomialSubtractionReduction_MB (

			
			int[] difference, int differenceOffset,
			final int[] minuend, int minuendOffset,
			final int [] subtrahend, int subtrahendOffset) {
		
		
	    for (int i=0; i < parameter.n; i++) {
	    	difference[i + differenceOffset] = (int)
	    			paulBarrettReduction_MB (minuend [minuendOffset + i] - subtrahend [subtrahendOffset + i]);
	    	
	    }			
	}
	
	public void polynomialSubtraction_MB (

			
			int[] difference, int differenceOffset,
			final int[] minuend, int minuendOffset,
			final int [] subtrahend, int subtrahendOffset) {
		
		
	    for (int i=0; i < parameter.n; i++) {
	    	difference[i + differenceOffset] = 
	    			minuend [minuendOffset + i] - subtrahend [subtrahendOffset + i];
	    	
	    }			
	}
	
	public void polynomialSubtraction (
			
		long[] difference, int differenceOffset,
		final long[] minuend, int minuendOffset,
		final long [] subtrahend, int subtrahendOffset) {
		
		for (int i = 0; i < parameter.n; i++) {
			
			difference[differenceOffset + i] = paulBarrettReduction (
				
					minuend[minuendOffset + i] - subtrahend[subtrahendOffset + i]
							
			);
			
		}
		
	}
	
	/********************************************************************************************************************
	 * Description:	Generation of Polynomial A for Heuristic qTESLA
	 * 
	 * @param		A									Polynomial to be Generated
	 * @param		seed								Kappa-Bit Seed
	 * @param		seedOffset							Starting Point of the Kappa-Bit Seed
	 *  
	 * @return		none
	 ********************************************************************************************************************/
	public void polynomialUniform (int[] A, byte[] seed, int seedOffset) {
		
		int position = 0;
		int i = 0;
		int numberOfByte = (parameter.qLogarithm + 7) / 8;
		int numberOfBlock = parameter.generateA;
		short dualModeSampler = 0;
		int value1;
		int value2;
		int value3;
		int value4;
		int mask = (1 << parameter.qLogarithm) - 1;
		
		byte[] buffer =

			new byte[FederalInformationProcessingStandard202.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * parameter.generateA];
		
		FederalInformationProcessingStandard202.customizableSecureHashAlgorithmKECCAK128Simple (
			
			buffer, 0,
			FederalInformationProcessingStandard202.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * parameter.generateA,
			dualModeSampler++,
			seed, seedOffset, QTESLAParameter.RANDOM
		
		);
		
		while (i < parameter.n) {
			
			if (position > 
			
				FederalInformationProcessingStandard202.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * numberOfBlock -
				Integer.SIZE / Byte.SIZE * numberOfByte
				
		) {
				
				numberOfBlock = 1;
				
				FederalInformationProcessingStandard202.customizableSecureHashAlgorithmKECCAK128Simple (
					
					buffer, 0,
					FederalInformationProcessingStandard202.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * numberOfBlock,
					dualModeSampler++,
					seed, seedOffset, QTESLAParameter.RANDOM
				
				);
				
				position = 0;
				
			}
			
			value1 = Common.load32 (buffer, position) & mask; 
			position += numberOfByte;
			
			value2 = Common.load32 (buffer, position) & mask;
			position += numberOfByte;
			
			value3 = Common.load32 (buffer, position) & mask;
			position += numberOfByte;
			
			value4 = Common.load32 (buffer, position) & mask;
			position += numberOfByte;
			
			if (value1 < parameter.q && i < parameter.n) {
				
				A[i++] = peterLawrenceMontgomeryReduction ((long) value1 * parameter.inverseNumberTheoreticTransform);

			}
			
			if (value2 < parameter.q && i < parameter.n) {
				
				A[i++] = peterLawrenceMontgomeryReduction ((long) value2 * parameter.inverseNumberTheoreticTransform);
				
			}
			
			if (value3 < parameter.q && i < parameter.n) {
				
				A[i++] = peterLawrenceMontgomeryReduction ((long) value3 * parameter.inverseNumberTheoreticTransform);
				
			}
			
			if (value4 < parameter.q && i < parameter.n) {
				
				A[i++] = peterLawrenceMontgomeryReduction ((long) value4 * parameter.inverseNumberTheoreticTransform);
				
			}
			
		}
		
	}
	
	/**************************************************************************************************************************************************************************************
	 * Description:	Generation of Polynomial A for Provably Secure qTESLA
	 * 
	 * @param		A									Polynomial to be Generated
	 * @param		seed								Kappa-Bit Seed
	 * @param		seedOffset							Starting Point of the Kappa-Bit Seed
	 * 
	 * @return		none
	 **************************************************************************************************************************************************************************************/
	public void polynomialUniform_MB (int[] A, byte[] seed, int seedOffset) {
		
		int position = 0;
		int i = 0;
		int numberOfByte = (parameter.qLogarithm + 7) / 8;
		int numberOfBlock = parameter.generateA;
		short dualModeSampler = 0;
		int value1;
		int value2;
		int value3;
		int value4;
		int mask = (1 << parameter.qLogarithm) - 1;
		
		byte[] buffer =

			new byte[FederalInformationProcessingStandard202.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * parameter.generateA];
		
		FederalInformationProcessingStandard202.customizableSecureHashAlgorithmKECCAK128Simple (
			
			buffer, 0,
			FederalInformationProcessingStandard202.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * parameter.generateA,
			dualModeSampler++,
			seed, seedOffset, QTESLAParameter.RANDOM
		
		);
		
		while (i < parameter.n * parameter.k) {
			
			if (position >
			
					FederalInformationProcessingStandard202.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * numberOfBlock -
					Integer.SIZE / Byte.SIZE * numberOfByte
					
			) {
				
				numberOfBlock = 1;
				
				FederalInformationProcessingStandard202.customizableSecureHashAlgorithmKECCAK128Simple (
					
					buffer, 0,
					FederalInformationProcessingStandard202.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * numberOfBlock,
					dualModeSampler++,
					seed, seedOffset, QTESLAParameter.RANDOM
				
				);
				
				position = 0;
				
			}
			
			value1 = Common.load32 (buffer, position) & mask; 
			position += numberOfByte;
			
			value2 = Common.load32 (buffer, position) & mask;
			position += numberOfByte;
			
			value3 = Common.load32 (buffer, position) & mask;
			position += numberOfByte;
			
			value4 = Common.load32 (buffer, position) & mask;
			position += numberOfByte;
			
			if (value1 < parameter.q && i < parameter.n * parameter.k) {
				
				A[i++] = peterLawrenceMontgomeryReduction_MB ((long) value1 * parameter.inverseNumberTheoreticTransform);

			}
			
			if (value2 < parameter.q && i < parameter.n * parameter.k) {
				
				A[i++] = peterLawrenceMontgomeryReduction_MB ((long) value2 * parameter.inverseNumberTheoreticTransform);
				
			}
			
			if (value3 < parameter.q && i < parameter.n * parameter.k) {
				
				A[i++] = peterLawrenceMontgomeryReduction_MB ((long) value3 * parameter.inverseNumberTheoreticTransform);
				
			}
			
			if (value4 < parameter.q && i < parameter.n * parameter.k) {
				
				A[i++] = peterLawrenceMontgomeryReduction_MB ((long) value4 * parameter.inverseNumberTheoreticTransform);
				
			}
			
		}
		
	}
	
	
	public void polynomialUniform (long[] A, byte[] seed, int seedOffset) {
		
		int position = 0;
		int i = 0;
		int numberOfByte = (parameter.qLogarithm + 7) / 8;
		int numberOfBlock = parameter.generateA;
		short dualModeSampler = 0;
		int value1;
		int value2;
		int value3;
		int value4;
		int mask = (1 << parameter.qLogarithm) - 1;
		
		byte[] buffer =

			new byte[FederalInformationProcessingStandard202.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * parameter.generateA];
		
		FederalInformationProcessingStandard202.customizableSecureHashAlgorithmKECCAK128Simple (
			
			buffer, 0,
			FederalInformationProcessingStandard202.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * parameter.generateA,
			dualModeSampler++,
			seed, seedOffset, QTESLAParameter.RANDOM
		
		);
		
		while (i < parameter.n * parameter.k) {
			
			if (position >
			
					FederalInformationProcessingStandard202.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * numberOfBlock -
					Integer.SIZE / Byte.SIZE * numberOfByte
					
			) {
				
				numberOfBlock = 1;
				
				FederalInformationProcessingStandard202.customizableSecureHashAlgorithmKECCAK128Simple (
					
					buffer, 0,
					FederalInformationProcessingStandard202.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * numberOfBlock,
					dualModeSampler++,
					seed, seedOffset, QTESLAParameter.RANDOM
				
				);
				
				position = 0;
				
			}
			
			value1 = Common.load32 (buffer, position) & mask; 
			position += numberOfByte;
			
			value2 = Common.load32 (buffer, position) & mask;
			position += numberOfByte;
			
			value3 = Common.load32 (buffer, position) & mask;
			position += numberOfByte;
			
			value4 = Common.load32 (buffer, position) & mask;
			position += numberOfByte;
			
			if (value1 < parameter.q && i < parameter.n * parameter.k) {
				
				A[i++] = peterLawrenceMontgomeryReductionP ((long) value1 * parameter.inverseNumberTheoreticTransform);

			}
			
			if (value2 < parameter.q && i < parameter.n * parameter.k) {
				
				A[i++] = peterLawrenceMontgomeryReductionP ((long) value2 * parameter.inverseNumberTheoreticTransform);
				
			}
			
			if (value3 < parameter.q && i < parameter.n * parameter.k) {
				
				A[i++] = peterLawrenceMontgomeryReductionP ((long) value3 * parameter.inverseNumberTheoreticTransform);
				
			}
			
			if (value4 < parameter.q && i < parameter.n * parameter.k) {
				
				A[i++] = peterLawrenceMontgomeryReductionP ((long) value4 * parameter.inverseNumberTheoreticTransform);
				
			}
			
		}
		
	}
	
	/********************************************************************************************
	 * Description:	Performs Sparse Polynomial Multiplication for A Value Needed During
	 *				Message Signification for Heuristic qTESLA
	 * 
	 * @param		product				Product of Two Polynomials
	 * @param		privateKey			Part of the Private Key
	 * @param		positionList		List of Indices of Non-Zero Elements in C
	 * @param		signList			List of Signs of Non-Zero Elements in C
	 * 
	 * @return		none
	 ********************************************************************************************/
	public void sparsePolynomialMultiplication16 (
			
		int[] product, final short[] privateKey, final int[] positionList, final short[] signList
		
	) {
		
		int position;
		
		Arrays.fill (product, 0);
		
		for (int i = 0; i < parameter.h; i++) {
			
			position = positionList[i];
			
			for (int j = 0; j < position; j++) {
				
				product[j] -= signList[i] * privateKey[parameter.n + j - position];
				
			}
			
			for (int j = position; j < parameter.n; j++) {
				
				product[j] += signList[i] * privateKey[j - position];
				
			}
			
		}
		
	}
	
	/*****************************************************************************************************************
	 * Description:	Performs Sparse Polynomial Multiplication for A Value Needed During Message Signification for
	 *				Provably Secure qTESLA
	 * 
	 * @param		product				Product of Two Polynomials
	 * @param		productOffset		Starting Point of the Product of Two Polynomials
	 * @param		privateKey			Part of the Private Key
	 * @param		privateKeyOffset	Starting Point of the Private Key
	 * @param		positionList		List of Indices of Non-Zero Elements in C
	 * @param		signList			List of Signs of Non-Zero Elements in C
	 * 
	 * @return		none
	 *****************************************************************************************************************/
	public void sparsePolynomialMultiplication8_MB (
			
			int[] product, int productOffset, final byte[] privateKey, int privateKeyOffset,
			final int[] positionList, final short[] signList
	
	) {
		
		int position;
		
		for (int j = 0; j < parameter.h; j++)
		{
			product[productOffset + j] = 0;
		}
		
		//Arrays.fill (product, 0);
		
		for (int i = 0; i < parameter.h; i++) {
			
			position = positionList[i];
			
			for (int j = 0; j < position; j++) {
				
				product[productOffset + j] = 
						product[productOffset + j] - signList[i] * privateKey[privateKeyOffset + parameter.n + j - position];
				
			}
			
			for (int j = position; j < parameter.n; j++) {
				
				product[productOffset + j] = 
						product[productOffset + j] + signList[i] * privateKey[privateKeyOffset + j - position];
						
			}
			
		}
		
	}
	
	public void sparsePolynomialMultiplication8 (
			
			long[] product, int productOffset, final byte[] privateKey, int privateKeyOffset,
			final int[] positionList, final short[] signList
	
	) {
		
		int position;
		
		Arrays.fill (product, 0L);
		
		for (int i = 0; i < parameter.h; i++) {
			
			position = positionList[i];
			
			for (int j = 0; j < position; j++) {
				
				product[productOffset + j] -= signList[i] * privateKey[privateKeyOffset + parameter.n + j - position];
				
			}
			
			for (int j = position; j < parameter.n; j++) {
				
				product[productOffset + j] += signList[i] * privateKey[privateKeyOffset + j - position];
						
			}
			
		}
		
	}
	
	/*****************************************************************************************
	 * Description:	Performs Sparse Polynomial Multiplication for A Value Needed During
	 *				Message Signification for Heuristic qTESLA
	 * 
	 * @param		product					Product of Two Polynomials
	 * @param		publicKey				Part of the Public Key
	 * @param		positionList			List of Indices of Non-Zero Elements in C
	 * @param		signList				List of Signs of Non-Zero Elements in C
	 * 
	 * @return		none
	 *****************************************************************************************/
	public void sparsePolynomialMultiplication32 (
			
		int[] product, final int[] publicKey, final int[] positionList, final short[] signList
		
	) {
		
		int position;
		
		Arrays.fill (product, 0);
		
		for (int i = 0; i < parameter.h; i++) {
			
			position = positionList[i];
			
			for (int j = 0; j < position; j++) {
				
				product[j] -= signList[i] * publicKey[parameter.n + j - position];
				
			}
			
			for (int j = position; j < parameter.n; j++) {
				
				product[j] += signList[i] * publicKey[j - position];
						
			}
			
		}
		
	}
	
	/*************************************************************************************************************
	 * Description:	Performs Sparse Polynomial Multiplication for A Value Needed During Message Signification for
	 *				Provably Secure qTESLA
	 * 
	 * @param		product					Product of Two Polynomials
	 * @param		productOffset			Starting Point of the Product of Two Polynomials
	 * @param		publicKey				Part of the Public Key
	 * @param		publicKeyOffset			Starting Point of the Public Key
	 * @param		positionList			List of Indices of Non-Zero Elements in C
	 * @param		signList				List of Signs of Non-Zero Elements in C
	 * 
	 * @return		none
	 *************************************************************************************************************/
	public void sparsePolynomialMultiplication32_MB (
			
			int[] product, int productOffset, final int[] publicKey, int publicKeyOffset,
			final int[] positionList, final short[] signList
			
		) {
			
			int position;	
			long temp[] = new long[parameter.n];
			
			for (int j = 0; j < parameter.h; j++)
			{
				product[productOffset + j] = 0;
			}
			
			for (int j = 0; j < parameter.n; j++)
			{
				temp[j] = 0;
			}
			
			
			
			
			for (int i = 0; i < parameter.h; i++) {
				
				position = positionList[i];
				
				for (int j = 0; j < position; j++) {
					
					temp[j] -= signList[i] * publicKey[publicKeyOffset + parameter.n + j - position];
					
				}
				
				for (int j = position; j < parameter.n; j++) {
					
					temp[j] += signList[i] * publicKey[publicKeyOffset + j - position];
							
				}
				
			}
			
			for (int i = 0; i < parameter.n; i++) {
				product[productOffset + i] = (int)paulBarrettReduction_MB (temp[i]);				
			}
			
		}
	
	public void sparsePolynomialMultiplication32 (
			
		long[] product, int productOffset, final int[] publicKey, int publicKeyOffset,
		final int[] positionList, final short[] signList
		
	) {
		
		int position;
		
		Arrays.fill (product, 0L);
		
		for (int i = 0; i < parameter.h; i++) {
			
			position = positionList[i];
			
			for (int j = 0; j < position; j++) {
				
				product[productOffset + j] -= signList[i] * publicKey[publicKeyOffset + parameter.n + j - position];
				
			}
			
			for (int j = position; j < parameter.n; j++) {
				
				product[productOffset + j] += signList[i] * publicKey[publicKeyOffset + j - position];
						
			}
			
		}
		
		for (int i = 0; i < parameter.n; i++) {
			
			product[productOffset + i] = paulBarrettReduction_MB (product[productOffset + i]);
			
		}
		
	}
	
}