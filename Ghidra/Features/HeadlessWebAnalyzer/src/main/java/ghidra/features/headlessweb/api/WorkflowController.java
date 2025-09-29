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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.features.headlessweb.service.WorkflowService;

/**
 * REST API controller for workflow management
 */
public class WorkflowController {
    
    private final WorkflowService workflowService;
    private final Gson gson;
    
    public WorkflowController(WorkflowService workflowService) {
        this.workflowService = workflowService;
        this.gson = new Gson();
    }
    
    /**
     * Get available example workflows
     * GET /api/workflows
     */
    public void getExampleWorkflows(Context ctx) {
        List<WorkflowService.Workflow> workflows = workflowService.getExampleWorkflows();
        ctx.json(workflows);
    }
    
    /**
     * Execute a workflow
     * POST /api/workflows/execute
     */
    public void executeWorkflow(Context ctx) {
        try {
            WorkflowExecutionRequest request = gson.fromJson(ctx.body(), WorkflowExecutionRequest.class);
            
            if (request.getWorkflowId() == null || request.getFilePath() == null) {
                ctx.status(400).json(new ErrorResponse("workflowId and filePath are required"));
                return;
            }
            
            Map<String, String> parameters = request.getParameters() != null ? 
                request.getParameters() : new HashMap<>();
            
            WorkflowService.WorkflowExecution execution = workflowService.executeWorkflow(
                request.getWorkflowId(), 
                request.getFilePath(), 
                parameters
            );
            
            ctx.json(execution);
            
        } catch (IllegalArgumentException e) {
            ctx.status(404).json(new ErrorResponse(e.getMessage()));
        } catch (Exception e) {
            ctx.status(500).json(new ErrorResponse("Failed to execute workflow: " + e.getMessage()));
        }
    }
    
    /**
     * Get workflow execution status
     * GET /api/workflows/{id}/status
     */
    public void getWorkflowStatus(Context ctx) {
        String executionId = ctx.pathParam("id");
        
        try {
            WorkflowService.WorkflowExecution execution = workflowService.getWorkflowStatus(executionId);
            ctx.json(execution);
        } catch (Exception e) {
            ctx.status(404).json(new ErrorResponse("Workflow execution not found"));
        }
    }
    
    // Request/Response classes
    private static class WorkflowExecutionRequest {
        private String workflowId;
        private String filePath;
        private Map<String, String> parameters;
        
        public String getWorkflowId() { return workflowId; }
        public void setWorkflowId(String workflowId) { this.workflowId = workflowId; }
        
        public String getFilePath() { return filePath; }
        public void setFilePath(String filePath) { this.filePath = filePath; }
        
        public Map<String, String> getParameters() { return parameters; }
        public void setParameters(Map<String, String> parameters) { this.parameters = parameters; }
    }
    
    private static class ErrorResponse {
        private final String error;
        
        public ErrorResponse(String error) {
            this.error = error;
        }
        
        public String getError() { return error; }
    }
}