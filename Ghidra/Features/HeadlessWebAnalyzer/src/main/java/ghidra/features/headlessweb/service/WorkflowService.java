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
package ghidra.features.headlessweb.service;

import java.util.*;

/**
 * Service for managing example analysis workflows
 */
public class WorkflowService {
    
    /**
     * Get predefined example workflows
     */
    public List<Workflow> getExampleWorkflows() {
        List<Workflow> workflows = new ArrayList<>();
        
        // Basic Malware Analysis Workflow
        workflows.add(new Workflow(
            "basic-malware-analysis",
            "Basic Malware Analysis",
            "Standard malware analysis with function identification and string extraction",
            Arrays.asList(
                "Import binary file",
                "Auto-analyze with default analyzers",
                "Extract function calls",
                "Extract strings",
                "Generate basic IOCs",
                "Categorize malware type"
            ),
            "analyzeHeadless /tmp/project MalwareProject -import {file} -postScript ExtractStrings.java -postScript ExtractFunctions.java"
        ));
        
        // Advanced Obfuscated Malware Analysis
        workflows.add(new Workflow(
            "advanced-obfuscated-analysis",
            "Advanced Obfuscated Malware Analysis",
            "Deep analysis for obfuscated malware with decompilation and pattern matching",
            Arrays.asList(
                "Import binary file",
                "Auto-analyze with aggressive settings",
                "Decompile all functions",
                "Apply string deobfuscation",
                "Extract crypto constants",
                "Identify packing/obfuscation techniques",
                "Generate comprehensive IOCs"
            ),
            "analyzeHeadless /tmp/project ObfuscatedProject -import {file} -postScript DeobfuscateStrings.java -postScript AnalyzeCrypto.java -postScript ExtractPackerInfo.java"
        ));
        
        // Network Behavior Analysis
        workflows.add(new Workflow(
            "network-behavior-analysis",
            "Network Behavior Analysis",
            "Focus on network-related functionality and C2 communication patterns",
            Arrays.asList(
                "Import binary file",
                "Auto-analyze network functions",
                "Extract network IOCs",
                "Identify C2 communication patterns",
                "Extract domain generation algorithms",
                "Analyze encryption protocols"
            ),
            "analyzeHeadless /tmp/project NetworkProject -import {file} -postScript NetworkAnalysis.java -postScript ExtractDomains.java"
        ));
        
        // Ransomware-Specific Analysis
        workflows.add(new Workflow(
            "ransomware-analysis",
            "Ransomware Analysis",
            "Specialized analysis for ransomware samples",
            Arrays.asList(
                "Import binary file",
                "Auto-analyze with focus on file operations",
                "Extract encryption routines",
                "Identify file extension targets",
                "Extract ransom note templates",
                "Analyze payment methods",
                "Extract kill switch mechanisms"
            ),
            "analyzeHeadless /tmp/project RansomwareProject -import {file} -postScript RansomwareAnalysis.java -postScript ExtractCrypto.java"
        ));
        
        // API Analysis Workflow
        workflows.add(new Workflow(
            "api-analysis",
            "Windows API Analysis",
            "Comprehensive analysis of Windows API usage patterns",
            Arrays.asList(
                "Import binary file",
                "Auto-analyze API calls",
                "Map API call sequences",
                "Identify suspicious API combinations",
                "Extract import table information",
                "Analyze dynamic API resolution"
            ),
            "analyzeHeadless /tmp/project APIProject -import {file} -postScript APIAnalysis.java -postScript ExtractImports.java"
        ));
        
        return workflows;
    }
    
    /**
     * Execute a specific workflow
     */
    public WorkflowExecution executeWorkflow(String workflowId, String filePath, Map<String, String> parameters) {
        Workflow workflow = getExampleWorkflows().stream()
            .filter(w -> w.getId().equals(workflowId))
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Workflow not found: " + workflowId));
        
        String executionId = UUID.randomUUID().toString();
        String command = workflow.getCommand().replace("{file}", filePath);
        
        // Apply any additional parameters
        for (Map.Entry<String, String> param : parameters.entrySet()) {
            command = command.replace("{" + param.getKey() + "}", param.getValue());
        }
        
        WorkflowExecution execution = new WorkflowExecution(
            executionId,
            workflowId,
            workflow.getName(),
            command,
            new Date()
        );
        
        execution.setStatus(WorkflowExecution.Status.RUNNING);
        execution.setCurrentStep(0);
        execution.setTotalSteps(workflow.getSteps().size());
        
        return execution;
    }
    
    /**
     * Get workflow execution status
     */
    public WorkflowExecution getWorkflowStatus(String executionId) {
        // Mock implementation - in real version would track actual execution
        WorkflowExecution execution = new WorkflowExecution(
            executionId,
            "basic-malware-analysis",
            "Basic Malware Analysis",
            "analyzeHeadless /tmp/project MalwareProject -import test.exe",
            new Date()
        );
        
        execution.setStatus(WorkflowExecution.Status.COMPLETED);
        execution.setCurrentStep(6);
        execution.setTotalSteps(6);
        execution.setCompletedTime(new Date());
        
        return execution;
    }
    
    /**
     * Workflow definition
     */
    public static class Workflow {
        private final String id;
        private final String name;
        private final String description;
        private final List<String> steps;
        private final String command;
        
        public Workflow(String id, String name, String description, List<String> steps, String command) {
            this.id = id;
            this.name = name;
            this.description = description;
            this.steps = steps;
            this.command = command;
        }
        
        // Getters
        public String getId() { return id; }
        public String getName() { return name; }
        public String getDescription() { return description; }
        public List<String> getSteps() { return steps; }
        public String getCommand() { return command; }
    }
    
    /**
     * Workflow execution tracking
     */
    public static class WorkflowExecution {
        public enum Status {
            QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED
        }
        
        private final String executionId;
        private final String workflowId;
        private final String workflowName;
        private final String command;
        private final Date startTime;
        private Status status;
        private int currentStep;
        private int totalSteps;
        private Date completedTime;
        private String errorMessage;
        
        public WorkflowExecution(String executionId, String workflowId, String workflowName, String command, Date startTime) {
            this.executionId = executionId;
            this.workflowId = workflowId;
            this.workflowName = workflowName;
            this.command = command;
            this.startTime = startTime;
            this.status = Status.QUEUED;
        }
        
        // Getters and Setters
        public String getExecutionId() { return executionId; }
        public String getWorkflowId() { return workflowId; }
        public String getWorkflowName() { return workflowName; }
        public String getCommand() { return command; }
        public Date getStartTime() { return startTime; }
        
        public Status getStatus() { return status; }
        public void setStatus(Status status) { this.status = status; }
        
        public int getCurrentStep() { return currentStep; }
        public void setCurrentStep(int currentStep) { this.currentStep = currentStep; }
        
        public int getTotalSteps() { return totalSteps; }
        public void setTotalSteps(int totalSteps) { this.totalSteps = totalSteps; }
        
        public Date getCompletedTime() { return completedTime; }
        public void setCompletedTime(Date completedTime) { this.completedTime = completedTime; }
        
        public String getErrorMessage() { return errorMessage; }
        public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
        
        public int getProgressPercentage() {
            if (totalSteps == 0) return 0;
            return (currentStep * 100) / totalSteps;
        }
    }
}