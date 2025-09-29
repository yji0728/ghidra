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
package ghidra.features.headlessweb.api;

import io.javalin.http.Context;
import com.google.gson.Gson;

import java.util.*;
import java.util.concurrent.ExecutorService;

import ghidra.features.headlessweb.model.AnalysisOptions;
import ghidra.features.headlessweb.model.AnalysisResult;
import ghidra.features.headlessweb.service.MalwareAnalysisService;

/**
 * REST API controller for batch analysis operations
 */
public class BatchController {
    
    private final MalwareAnalysisService analysisService;
    private final ExecutorService executorService;
    private final Gson gson;
    private final Map<String, BatchAnalysisJob> batchJobs = new HashMap<>();
    
    public BatchController(MalwareAnalysisService analysisService, ExecutorService executorService) {
        this.analysisService = analysisService;
        this.executorService = executorService;
        this.gson = new Gson();
    }
    
    /**
     * Submit batch analysis job
     * POST /api/batch/analyze
     */
    public void submitBatchAnalysis(Context ctx) {
        try {
            BatchAnalysisRequest request = gson.fromJson(ctx.body(), BatchAnalysisRequest.class);
            
            if (request.getFilePaths() == null || request.getFilePaths().isEmpty()) {
                ctx.status(400).json(new ErrorResponse("filePaths is required"));
                return;
            }
            
            String batchId = UUID.randomUUID().toString();
            AnalysisOptions options = request.getOptions() != null ? request.getOptions() : new AnalysisOptions();
            
            BatchAnalysisJob job = new BatchAnalysisJob(
                batchId,
                request.getFilePaths(),
                options,
                new Date()
            );
            
            batchJobs.put(batchId, job);
            
            // Start batch processing
            executorService.submit(() -> processBatchJob(job));
            
            ctx.json(new BatchResponse(batchId, "Batch analysis started", job.getFilePaths().size()));
            
        } catch (Exception e) {
            ctx.status(500).json(new ErrorResponse("Failed to start batch analysis: " + e.getMessage()));
        }
    }
    
    /**
     * Get batch analysis status
     * GET /api/batch/status/{id}
     */
    public void getBatchStatus(Context ctx) {
        String batchId = ctx.pathParam("id");
        BatchAnalysisJob job = batchJobs.get(batchId);
        
        if (job == null) {
            ctx.status(404).json(new ErrorResponse("Batch job not found"));
            return;
        }
        
        BatchStatusResponse response = new BatchStatusResponse(
            job.getBatchId(),
            job.getStatus(),
            job.getTotalFiles(),
            job.getCompletedFiles(),
            job.getFailedFiles(),
            job.getStartTime(),
            job.getCompletedTime(),
            job.getErrorMessage()
        );
        
        ctx.json(response);
    }
    
    /**
     * Get batch analysis results
     * GET /api/batch/results/{id}
     */
    public void getBatchResults(Context ctx) {
        String batchId = ctx.pathParam("id");
        BatchAnalysisJob job = batchJobs.get(batchId);
        
        if (job == null) {
            ctx.status(404).json(new ErrorResponse("Batch job not found"));
            return;
        }
        
        BatchResultsResponse response = new BatchResultsResponse(
            job.getBatchId(),
            job.getResults(),
            job.getFailures()
        );
        
        ctx.json(response);
    }
    
    private void processBatchJob(BatchAnalysisJob job) {
        try {
            job.setStatus(BatchAnalysisJob.Status.RUNNING);
            
            for (String filePath : job.getFilePaths()) {
                try {
                    // Process each file
                    // Note: In real implementation, this would use actual file objects
                    // For now, we'll create mock results
                    AnalysisResult result = createMockResult(filePath);
                    job.addResult(result);
                    job.incrementCompleted();
                    
                } catch (Exception e) {
                    job.addFailure(filePath, e.getMessage());
                    job.incrementFailed();
                }
            }
            
            job.setStatus(BatchAnalysisJob.Status.COMPLETED);
            job.setCompletedTime(new Date());
            
        } catch (Exception e) {
            job.setStatus(BatchAnalysisJob.Status.FAILED);
            job.setErrorMessage(e.getMessage());
            job.setCompletedTime(new Date());
        }
    }
    
    private AnalysisResult createMockResult(String filePath) {
        AnalysisResult result = new AnalysisResult();
        result.setAnalysisId(UUID.randomUUID().toString());
        result.setFileName(filePath.substring(filePath.lastIndexOf('/') + 1));
        result.setTimestamp(new Date());
        result.setFileType("PE");
        result.setMalwareCategory("Unknown");
        return result;
    }
    
    // Data classes
    private static class BatchAnalysisRequest {
        private List<String> filePaths;
        private AnalysisOptions options;
        
        public List<String> getFilePaths() { return filePaths; }
        public void setFilePaths(List<String> filePaths) { this.filePaths = filePaths; }
        
        public AnalysisOptions getOptions() { return options; }
        public void setOptions(AnalysisOptions options) { this.options = options; }
    }
    
    private static class BatchResponse {
        private final String batchId;
        private final String message;
        private final int totalFiles;
        
        public BatchResponse(String batchId, String message, int totalFiles) {
            this.batchId = batchId;
            this.message = message;
            this.totalFiles = totalFiles;
        }
        
        public String getBatchId() { return batchId; }
        public String getMessage() { return message; }
        public int getTotalFiles() { return totalFiles; }
    }
    
    private static class BatchStatusResponse {
        private final String batchId;
        private final BatchAnalysisJob.Status status;
        private final int totalFiles;
        private final int completedFiles;
        private final int failedFiles;
        private final Date startTime;
        private final Date completedTime;
        private final String errorMessage;
        
        public BatchStatusResponse(String batchId, BatchAnalysisJob.Status status, int totalFiles, 
                                 int completedFiles, int failedFiles, Date startTime, 
                                 Date completedTime, String errorMessage) {
            this.batchId = batchId;
            this.status = status;
            this.totalFiles = totalFiles;
            this.completedFiles = completedFiles;
            this.failedFiles = failedFiles;
            this.startTime = startTime;
            this.completedTime = completedTime;
            this.errorMessage = errorMessage;
        }
        
        // Getters
        public String getBatchId() { return batchId; }
        public BatchAnalysisJob.Status getStatus() { return status; }
        public int getTotalFiles() { return totalFiles; }
        public int getCompletedFiles() { return completedFiles; }
        public int getFailedFiles() { return failedFiles; }
        public Date getStartTime() { return startTime; }
        public Date getCompletedTime() { return completedTime; }
        public String getErrorMessage() { return errorMessage; }
        
        public int getProgressPercentage() {
            if (totalFiles == 0) return 0;
            return (completedFiles * 100) / totalFiles;
        }
    }
    
    private static class BatchResultsResponse {
        private final String batchId;
        private final List<AnalysisResult> results;
        private final Map<String, String> failures;
        
        public BatchResultsResponse(String batchId, List<AnalysisResult> results, Map<String, String> failures) {
            this.batchId = batchId;
            this.results = results;
            this.failures = failures;
        }
        
        public String getBatchId() { return batchId; }
        public List<AnalysisResult> getResults() { return results; }
        public Map<String, String> getFailures() { return failures; }
    }
    
    private static class BatchAnalysisJob {
        public enum Status {
            QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED
        }
        
        private final String batchId;
        private final List<String> filePaths;
        private final AnalysisOptions options;
        private final Date startTime;
        private Status status;
        private Date completedTime;
        private String errorMessage;
        private int completedFiles = 0;
        private int failedFiles = 0;
        private final List<AnalysisResult> results = new ArrayList<>();
        private final Map<String, String> failures = new HashMap<>();
        
        public BatchAnalysisJob(String batchId, List<String> filePaths, AnalysisOptions options, Date startTime) {
            this.batchId = batchId;
            this.filePaths = filePaths;
            this.options = options;
            this.startTime = startTime;
            this.status = Status.QUEUED;
        }
        
        // Getters and operations
        public String getBatchId() { return batchId; }
        public List<String> getFilePaths() { return filePaths; }
        public AnalysisOptions getOptions() { return options; }
        public Date getStartTime() { return startTime; }
        public Status getStatus() { return status; }
        public void setStatus(Status status) { this.status = status; }
        public Date getCompletedTime() { return completedTime; }
        public void setCompletedTime(Date completedTime) { this.completedTime = completedTime; }
        public String getErrorMessage() { return errorMessage; }
        public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
        public int getTotalFiles() { return filePaths.size(); }
        public int getCompletedFiles() { return completedFiles; }
        public int getFailedFiles() { return failedFiles; }
        public List<AnalysisResult> getResults() { return results; }
        public Map<String, String> getFailures() { return failures; }
        
        public void incrementCompleted() { completedFiles++; }
        public void incrementFailed() { failedFiles++; }
        public void addResult(AnalysisResult result) { results.add(result); }
        public void addFailure(String filePath, String error) { failures.put(filePath, error); }
    }
    
    private static class ErrorResponse {
        private final String error;
        
        public ErrorResponse(String error) {
            this.error = error;
        }
        
        public String getError() { return error; }
    }
}