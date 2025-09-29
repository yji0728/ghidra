/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.features.headlessweb.model;

import java.util.List;
import java.util.Map;

/**
 * Machine Learning-based code pattern analysis results
 */
public class CodePatternAnalysis {
    private double obfuscationProbability;
    private List<String> detectedPackers;
    private List<String> codePatterns;
    private Map<String, Double> malwareFamilyProbabilities;
    private List<String> suspiciousSequences;
    private String analysisModel;
    private double confidence;
    
    public CodePatternAnalysis() {}
    
    // Getters and Setters
    public double getObfuscationProbability() { return obfuscationProbability; }
    public void setObfuscationProbability(double obfuscationProbability) { this.obfuscationProbability = obfuscationProbability; }
    
    public List<String> getDetectedPackers() { return detectedPackers; }
    public void setDetectedPackers(List<String> detectedPackers) { this.detectedPackers = detectedPackers; }
    
    public List<String> getCodePatterns() { return codePatterns; }
    public void setCodePatterns(List<String> codePatterns) { this.codePatterns = codePatterns; }
    
    public Map<String, Double> getMalwareFamilyProbabilities() { return malwareFamilyProbabilities; }
    public void setMalwareFamilyProbabilities(Map<String, Double> malwareFamilyProbabilities) { this.malwareFamilyProbabilities = malwareFamilyProbabilities; }
    
    public List<String> getSuspiciousSequences() { return suspiciousSequences; }
    public void setSuspiciousSequences(List<String> suspiciousSequences) { this.suspiciousSequences = suspiciousSequences; }
    
    public String getAnalysisModel() { return analysisModel; }
    public void setAnalysisModel(String analysisModel) { this.analysisModel = analysisModel; }
    
    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }
}