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
import io.javalin.http.UploadedFile;
import com.google.gson.Gson;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

import ghidra.features.headlessweb.model.*;
import ghidra.features.headlessweb.service.MalwareAnalysisService;

/**
 * REST API controller for malware analysis operations
 */
public class AnalysisController {
    
    private final MalwareAnalysisService analysisService;
    private final ExecutorService executorService;
    private final Gson gson;
    private final Path uploadDir;
    
    public AnalysisController(MalwareAnalysisService analysisService, ExecutorService executorService) {
        this.analysisService = analysisService;
        this.executorService = executorService;
        this.gson = new Gson();
        
        try {
            this.uploadDir = Files.createTempDirectory("ghidra-uploads");
        } catch (IOException e) {
            throw new RuntimeException("Failed to create upload directory", e);
        }
    }
    
    /**
     * Upload and analyze a file
     * POST /api/analyze/file
     */
    public void analyzeFile(Context ctx) {
        try {
            UploadedFile uploadedFile = ctx.uploadedFile("file");
            if (uploadedFile == null) {
                ctx.status(400).json(new ErrorResponse("No file uploaded"));
                return;
            }
            
            // Save uploaded file
            File tempFile = uploadDir.resolve(uploadedFile.filename()).toFile();
            uploadedFile.content().transferTo(tempFile.toPath());
            
            // Parse analysis options from form data or use defaults
            AnalysisOptions options = parseAnalysisOptions(ctx);
            
            // Start analysis asynchronously
            CompletableFuture<AnalysisResult> future = analysisService.analyzeFile(tempFile, options);
            
            // Return analysis ID immediately
            String analysisId = future.thenApply(AnalysisResult::getAnalysisId).join();
            ctx.json(new AnalysisResponse(analysisId, "Analysis started"));
            
        } catch (Exception e) {
            ctx.status(500).json(new ErrorResponse("Failed to start analysis: " + e.getMessage()));
        }
    }
    
    /**
     * Execute custom headless command
     * POST /api/analyze/custom
     */
    public void executeCustomCommand(Context ctx) {
        try {
            CustomCommandRequest request = gson.fromJson(ctx.body(), CustomCommandRequest.class);
            if (request.getCommand() == null || request.getCommand().trim().isEmpty()) {
                ctx.status(400).json(new ErrorResponse("Command is required"));
                return;
            }
            
            AnalysisOptions options = request.getOptions() != null ? request.getOptions() : new AnalysisOptions();
            
            // Execute command asynchronously
            CompletableFuture<AnalysisResult> future = analysisService.executeCustomCommand(request.getCommand(), options);
            
            // Return analysis ID immediately
            String analysisId = future.thenApply(AnalysisResult::getAnalysisId).join();
            ctx.json(new AnalysisResponse(analysisId, "Custom command execution started"));
            
        } catch (Exception e) {
            ctx.status(500).json(new ErrorResponse("Failed to execute command: " + e.getMessage()));
        }
    }
    
    /**
     * Get analysis status
     * GET /api/analyze/status/{id}
     */
    public void getAnalysisStatus(Context ctx) {
        String analysisId = ctx.pathParam("id");
        AnalysisStatus status = analysisService.getAnalysisStatus(analysisId);
        
        if (status == null) {
            ctx.status(404).json(new ErrorResponse("Analysis not found"));
            return;
        }
        
        ctx.json(status);
    }
    
    /**
     * Get analysis result
     * GET /api/analyze/result/{id}
     */
    public void getAnalysisResult(Context ctx) {
        String analysisId = ctx.pathParam("id");
        AnalysisResult result = analysisService.getAnalysisResult(analysisId);
        
        if (result == null) {
            ctx.status(404).json(new ErrorResponse("Analysis result not found"));
            return;
        }
        
        ctx.json(result);
    }
    
    /**
     * Get all analysis results
     * GET /api/analyze/results
     */
    public void getAllResults(Context ctx) {
        List<AnalysisResult> results = analysisService.getAllResults();
        ctx.json(results);
    }
    
    /**
     * Extract IOCs from analysis
     * GET /api/extract/iocs/{analysisId}
     */
    public void extractIOCs(Context ctx) {
        String analysisId = ctx.pathParam("analysisId");
        try {
            IOCResult iocs = analysisService.extractIOCs(analysisId);
            ctx.json(iocs);
        } catch (IllegalArgumentException e) {
            ctx.status(404).json(new ErrorResponse(e.getMessage()));
        }
    }
    
    /**
     * Extract function calls from analysis
     * GET /api/extract/functions/{analysisId}
     */
    public void extractFunctions(Context ctx) {
        String analysisId = ctx.pathParam("analysisId");
        try {
            List<FunctionCall> functions = analysisService.extractFunctions(analysisId);
            ctx.json(functions);
        } catch (IllegalArgumentException e) {
            ctx.status(404).json(new ErrorResponse(e.getMessage()));
        }
    }
    
    /**
     * Extract interesting strings from analysis
     * GET /api/extract/strings/{analysisId}
     */
    public void extractStrings(Context ctx) {
        String analysisId = ctx.pathParam("analysisId");
        try {
            List<String> strings = analysisService.extractStrings(analysisId);
            ctx.json(strings);
        } catch (IllegalArgumentException e) {
            ctx.status(404).json(new ErrorResponse(e.getMessage()));
        }
    }
    
    /**
     * Get available malware categories
     * GET /api/malware/categories
     */
    public void getMalwareCategories(Context ctx) {
        List<String> categories = analysisService.getMalwareCategories();
        ctx.json(categories);
    }
    
    /**
     * Categorize malware
     * POST /api/malware/categorize/{analysisId}
     */
    public void categorizeMalware(Context ctx) {
        String analysisId = ctx.pathParam("analysisId");
        try {
            String category = analysisService.categorizeMalware(analysisId);
            ctx.json(new CategoryResponse(category));
        } catch (IllegalArgumentException e) {
            ctx.status(404).json(new ErrorResponse(e.getMessage()));
        }
    }
    
    /**
     * Get malware by category
     * GET /api/malware/category/{category}
     */
    public void getMalwareByCategory(Context ctx) {
        String category = ctx.pathParam("category");
        List<AnalysisResult> results = analysisService.getMalwareByCategory(category);
        ctx.json(results);
    }
    
    /**
     * Analyze code patterns using ML
     * POST /api/ml/analyze-patterns/{analysisId}
     */
    public void analyzeCodePatterns(Context ctx) {
        String analysisId = ctx.pathParam("analysisId");
        
        // Mock implementation - in real version would use actual ML models
        CodePatternAnalysis analysis = new CodePatternAnalysis();
        analysis.setObfuscationProbability(0.75);
        analysis.setAnalysisModel("DeepMalware-v1.0");
        analysis.setConfidence(0.85);
        
        ctx.json(analysis);
    }
    
    /**
     * Deobfuscate code using ML
     * POST /api/ml/deobfuscate/{analysisId}
     */
    public void deobfuscateCode(Context ctx) {
        String analysisId = ctx.pathParam("analysisId");
        
        // Mock implementation - in real version would use actual ML deobfuscation
        DeobfuscationResult result = new DeobfuscationResult();
        result.setObfuscated(true);
        result.setObfuscationType("String Encryption");
        result.setDeobfuscationMethod("Neural Network Decoder");
        result.setSuccessRate(0.92);
        
        ctx.json(result);
    }
    
    private AnalysisOptions parseAnalysisOptions(Context ctx) {
        AnalysisOptions options = new AnalysisOptions();
        
        // Parse options from form parameters
        String analysisEnabled = ctx.formParam("analysisEnabled");
        if (analysisEnabled != null) {
            options.setAnalysisEnabled(Boolean.parseBoolean(analysisEnabled));
        }
        
        String extractStrings = ctx.formParam("extractStrings");
        if (extractStrings != null) {
            options.setExtractStrings(Boolean.parseBoolean(extractStrings));
        }
        
        String useML = ctx.formParam("useML");
        if (useML != null) {
            options.setUseML(Boolean.parseBoolean(useML));
        }
        
        return options;
    }
    
    // Response classes
    private static class AnalysisResponse {
        private final String analysisId;
        private final String message;
        
        public AnalysisResponse(String analysisId, String message) {
            this.analysisId = analysisId;
            this.message = message;
        }
        
        public String getAnalysisId() { return analysisId; }
        public String getMessage() { return message; }
    }
    
    private static class ErrorResponse {
        private final String error;
        
        public ErrorResponse(String error) {
            this.error = error;
        }
        
        public String getError() { return error; }
    }
    
    private static class CategoryResponse {
        private final String category;
        
        public CategoryResponse(String category) {
            this.category = category;
        }
        
        public String getCategory() { return category; }
    }
    
    private static class CustomCommandRequest {
        private String command;
        private AnalysisOptions options;
        
        public String getCommand() { return command; }
        public void setCommand(String command) { this.command = command; }
        
        public AnalysisOptions getOptions() { return options; }
        public void setOptions(AnalysisOptions options) { this.options = options; }
    }
}