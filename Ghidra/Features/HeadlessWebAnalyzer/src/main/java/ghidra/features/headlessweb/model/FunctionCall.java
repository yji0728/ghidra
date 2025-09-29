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

/**
 * Represents a function call found in the analyzed binary
 */
public class FunctionCall {
    private String functionName;
    private String address;
    private List<String> parameters;
    private String returnType;
    private String callingConvention;
    private boolean isImported;
    private String moduleName;
    
    public FunctionCall() {}
    
    public FunctionCall(String functionName, String address, List<String> parameters) {
        this.functionName = functionName;
        this.address = address;
        this.parameters = parameters;
    }
    
    // Getters and Setters
    public String getFunctionName() { return functionName; }
    public void setFunctionName(String functionName) { this.functionName = functionName; }
    
    public String getAddress() { return address; }
    public void setAddress(String address) { this.address = address; }
    
    public List<String> getParameters() { return parameters; }
    public void setParameters(List<String> parameters) { this.parameters = parameters; }
    
    public String getReturnType() { return returnType; }
    public void setReturnType(String returnType) { this.returnType = returnType; }
    
    public String getCallingConvention() { return callingConvention; }
    public void setCallingConvention(String callingConvention) { this.callingConvention = callingConvention; }
    
    public boolean isImported() { return isImported; }
    public void setImported(boolean imported) { isImported = imported; }
    
    public String getModuleName() { return moduleName; }
    public void setModuleName(String moduleName) { this.moduleName = moduleName; }
}