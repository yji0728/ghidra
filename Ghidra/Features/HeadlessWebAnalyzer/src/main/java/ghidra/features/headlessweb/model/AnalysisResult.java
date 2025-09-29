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

import java.util.Date;
import java.util.List;

/**
 * Result of malware analysis containing extracted information
 */
public class AnalysisResult {
    private String analysisId;
    private String fileName;
    private long fileSize;
    private String fileHash;
    private String fileType;
    private Date timestamp;
    private String customCommand;
    private String malwareCategory;
    
    // Analysis results
    private List<FunctionCall> functionCalls;
    private IOCResult iocs;
    private List<String> interestingStrings;
    private CodePatternAnalysis codePatterns;
    private DeobfuscationResult deobfuscation;
    
    // Constructors
    public AnalysisResult() {}
    
    public AnalysisResult(String analysisId) {
        this.analysisId = analysisId;
        this.timestamp = new Date();
    }
    
    // Getters and Setters
    public String getAnalysisId() { return analysisId; }
    public void setAnalysisId(String analysisId) { this.analysisId = analysisId; }
    
    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }
    
    public long getFileSize() { return fileSize; }
    public void setFileSize(long fileSize) { this.fileSize = fileSize; }
    
    public String getFileHash() { return fileHash; }
    public void setFileHash(String fileHash) { this.fileHash = fileHash; }
    
    public String getFileType() { return fileType; }
    public void setFileType(String fileType) { this.fileType = fileType; }
    
    public Date getTimestamp() { return timestamp; }
    public void setTimestamp(Date timestamp) { this.timestamp = timestamp; }
    
    public String getCustomCommand() { return customCommand; }
    public void setCustomCommand(String customCommand) { this.customCommand = customCommand; }
    
    public String getMalwareCategory() { return malwareCategory; }
    public void setMalwareCategory(String malwareCategory) { this.malwareCategory = malwareCategory; }
    
    public List<FunctionCall> getFunctionCalls() { return functionCalls; }
    public void setFunctionCalls(List<FunctionCall> functionCalls) { this.functionCalls = functionCalls; }
    
    public IOCResult getIocs() { return iocs; }
    public void setIocs(IOCResult iocs) { this.iocs = iocs; }
    
    public List<String> getInterestingStrings() { return interestingStrings; }
    public void setInterestingStrings(List<String> interestingStrings) { this.interestingStrings = interestingStrings; }
    
    public CodePatternAnalysis getCodePatterns() { return codePatterns; }
    public void setCodePatterns(CodePatternAnalysis codePatterns) { this.codePatterns = codePatterns; }
    
    public DeobfuscationResult getDeobfuscation() { return deobfuscation; }
    public void setDeobfuscation(DeobfuscationResult deobfuscation) { this.deobfuscation = deobfuscation; }
}