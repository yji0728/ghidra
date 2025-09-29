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

/**
 * Status of an analysis operation
 */
public class AnalysisStatus {
    public enum Status {
        QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED
    }
    
    private String analysisId;
    private Status status;
    private String message;
    private Date startTime;
    private Date lastUpdated;
    private int progress; // 0-100
    
    public AnalysisStatus(String analysisId) {
        this.analysisId = analysisId;
        this.status = Status.QUEUED;
        this.startTime = new Date();
        this.lastUpdated = new Date();
        this.progress = 0;
    }
    
    // Getters and Setters
    public String getAnalysisId() { return analysisId; }
    
    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
    
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    
    public Date getStartTime() { return startTime; }
    public void setStartTime(Date startTime) { this.startTime = startTime; }
    
    public Date getLastUpdated() { return lastUpdated; }
    public void setLastUpdated(Date lastUpdated) { this.lastUpdated = lastUpdated; }
    
    public int getProgress() { return progress; }
    public void setProgress(int progress) { this.progress = progress; }
}