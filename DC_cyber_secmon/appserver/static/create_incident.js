require([
    "splunkjs/mvc",
    "splunkjs/mvc/searchmanager",
    "jquery",
    "splunkjs/mvc/simplexml/ready!"
], function(mvc, SearchManager, $) {
    
    console.log("Create Incident JavaScript loaded successfully");
    
    var tokens = mvc.Components.get("default");
    var submitted_tokens = mvc.Components.get("submitted");
    
    // Wait for DOM to be ready
    $(document).ready(function() {
        
        // ========================================================
        // CREATE INCIDENT HANDLER
        // ========================================================
        $(document).on("click", "#create_incident_btn", function() {
            
            console.log("Create Incident button clicked");
            
            // Get token values
            var alert_id = tokens.get("selected_alert_id");
            var description = tokens.get("incident_description") || "Investigate alert";
            var assigned_to = tokens.get("incident_assigned_to") || "unassigned";
            var notes = tokens.get("incident_notes") || "";
            
            console.log("Alert ID:", alert_id);
            console.log("Description:", description);
            console.log("Assigned To:", assigned_to);
            
            // Validate that an alert is selected
            if (!alert_id || alert_id === "") {
                alert("Please select an alert first!");
                console.error("No alert selected");
                return;
            }
            
            // Generate unique incident ID (timestamp-based)
            var incident_id = "INC-" + Date.now();
            console.log("Generated Incident ID:", incident_id);
            
            // Escape quotes in user input
            var escaped_description = description.replace(/"/g, '\\"').replace(/\\/g, '\\\\');
            var escaped_notes = notes.replace(/"/g, '\\"').replace(/\\/g, '\\\\');
            
            // Build the search query
            var searchQuery = 'index=notable alert_id="' + alert_id + '" earliest=-24h latest=now | head 1 ' +
                            '| eval incident_id="' + incident_id + '" ' +
                            '| eval description="' + escaped_description + '" ' +
                            '| eval assigned_to="' + assigned_to + '" ' +
                            '| eval notes="' + escaped_notes + '" ' +
                            '| eval status="open" ' +
                            '| eval created_time=now() ' +
                            '| eval updated_time=now() ' +
                            '| table incident_id, alert_id, alert_name, severity, status, assigned_to, created_time, updated_time, src_entity, mitre_technique_id, mitre_tactic, description, notes ' +
                            '| outputlookup append=true security_incidents';
            
            console.log("Search Query:", searchQuery);
            
            // Show loading message
            $("#create_incident_btn").prop("disabled", true).text("Creating...");
            
            // Create and execute the search
            var searchManager = new SearchManager({
                id: "create_incident_search_" + Date.now(),
                earliest_time: "-24h",
                latest_time: "now",
                search: searchQuery,
                autostart: true
            });
            
            // Handle search completion
            searchManager.on("search:done", function(properties) {
                console.log("Search completed successfully");
                alert("Incident " + incident_id + " created successfully!");
                
                // Re-enable button
                $("#create_incident_btn").prop("disabled", false).text("Create Incident");
                
                // Clear form
                tokens.set("selected_alert_id", "");
                tokens.set("incident_description", "");
                tokens.set("incident_notes", "");
                submitted_tokens.set("selected_alert_id", "");
                
                // Reload page to refresh incident list
                setTimeout(function() {
                    location.reload();
                }, 1000);
            });
            
            // Handle search errors
            searchManager.on("search:error", function(properties) {
                console.error("Search error:", properties);
                alert("Error creating incident. Check Splunk logs and browser console.");
                $("#create_incident_btn").prop("disabled", false).text("Create Incident");
            });
            
            // Handle search failures
            searchManager.on("search:fail", function(properties) {
                console.error("Search failed:", properties);
                alert("Search failed. Check permissions and KVStore configuration.");
                $("#create_incident_btn").prop("disabled", false).text("Create Incident");
            });
        });
        
        console.log("Create Incident event handler registered");
        
        // ========================================================
        // UPDATE INCIDENT HANDLER
        // ========================================================
       
// ========================================================
// UPDATE INCIDENT HANDLER
// ========================================================
$(document).on("click", "#update_incident_btn", function() {
    
    console.log("Update Incident button clicked");
    
    // Get token values using the SplunkJS/MVC tokens object (this is the correct way)
    // 1. Get the incident ID selected from the dropdown
    var incident_id = tokens.get("update_incident_id"); 

    // 2. Get the new status from the 'new_status' dropdown
    var new_status = tokens.get("new_status") || "open";
    
    // 3. Get the new assigned user from the 'new_assigned_to' dropdown
    var new_assigned_to = tokens.get("new_assigned_to") || "unassigned";
    
    console.log("Incident ID:", incident_id);
    console.log("New Status:", new_status);
    console.log("New Assigned To:", new_assigned_to);
    
    // Validate incident ID
    if (!incident_id || incident_id === "") {
        alert("Please select an Incident ID to update!");
        console.error("No Incident ID selected for update");
        return;
    }
    
    // Build the update search query
    // The query looks good: it uses outputlookup to overwrite the KVStore
    var updateQuery = '| inputlookup security_incidents ' +
                    '| eval status=if(incident_id="' + incident_id + '", "' + new_status + '", status) ' +
                    '| eval assigned_to=if(incident_id="' + incident_id + '", "' + new_assigned_to + '", assigned_to) ' +
                    '| eval updated_time=if(incident_id="' + incident_id + '", now(), updated_time) ' +
                    '| outputlookup security_incidents';
    
    console.log("Update Search Query:", updateQuery);
    
    // Show loading message
    $("#update_incident_btn").prop("disabled", true).text("Updating...");
    
    // Create and execute the search
    var updateSearchManager = new SearchManager({
        id: "update_incident_search_" + Date.now(),
        earliest_time: "-1m",
        latest_time: "now",
        search: updateQuery,
        autostart: true
    });
    
    // Handle search completion
    updateSearchManager.on("search:done", function(properties) {
        console.log("Update search completed successfully");
        alert("Incident " + incident_id + " updated successfully!\nStatus: " + new_status + "\nAssigned To: " + new_assigned_to);
        
        // Re-enable button
        $("#update_incident_btn").prop("disabled", false).text("Update Incident");
        
        // Clear tokens by setting them to a blank value
        tokens.set("update_incident_id", "");
        tokens.set("new_status", "investigating"); // Set back to default value
        tokens.set("new_assigned_to", "unassigned"); // Set back to default value

        // You should also clear the submitted token to ensure the dependent panel hides
        submitted_tokens.set("update_incident_id", ""); 

        // Reload page to refresh incident list
        setTimeout(function() {
            location.reload();
        }, 1000);
    });
    
    // Handle search errors
    updateSearchManager.on("search:error", function(properties) {
        console.error("Update Search Error:", properties);
        alert("Error updating incident. Check browser console and Splunk logs.");
        $("#update_incident_btn").prop("disabled", false).text("Update Incident");
    });
    
    // Handle search failures
    updateSearchManager.on("search:fail", function(properties) {
        console.error("Update Search Failed:", properties);
        alert("Search failed. Check permissions and KVStore configuration.");
        $("#update_incident_btn").prop("disabled", false).text("Update Incident");
    });
});

console.log("Update Incident event handler registered");


// ========================================================
// DELETE INCIDENT HANDLER
// ========================================================
$(document).on("click", "#delete_incident_btn", function() {
    
    console.log("Delete Incident button clicked");
    
    // Get the incident ID selected from the dropdown (using the token defined in XML)
    var incident_id = tokens.get("delete_incident_id"); 

    console.log("Incident ID to delete:", incident_id);
    
    // Validate incident ID
    if (!incident_id || incident_id === "") {
        alert("Please select an Incident ID to delete!");
        console.error("No Incident ID selected for deletion");
        return;
    }

    // Confirmation before proceeding with irreversible action
    if (!confirm("ARE YOU SURE you want to permanently delete Incident " + incident_id + "? This action cannot be undone.")) {
        console.log("Deletion cancelled by user.");
        return;
    }
    
    // Build the delete search query
    // This query loads ALL incidents, filters out the one matching the incident_id, 
    // and then overwrites the lookup with the remaining incidents.
    var deleteQuery = '| inputlookup security_incidents ' +
                    '| search NOT incident_id="' + incident_id + '" ' + // Filter out the one to delete
                    '| outputlookup security_incidents'; // Overwrite the lookup with the remaining data
    
    console.log("Delete Search Query:", deleteQuery);
    
    // Show loading message
    $("#delete_incident_btn").prop("disabled", true).text("Deleting...");
    
    // Create and execute the search
    var deleteSearchManager = new SearchManager({
        id: "delete_incident_search_" + Date.now(),
        earliest_time: "-1m",
        latest_time: "now",
        search: deleteQuery,
        autostart: true
    });
    
    // Handle search completion
    deleteSearchManager.on("search:done", function(properties) {
        console.log("Delete search completed successfully");
        alert("Incident " + incident_id + " permanently deleted.");
        
        // Re-enable button
        $("#delete_incident_btn").prop("disabled", false).text("Permanently Delete Incident " + incident_id);
        
        // Clear tokens
        tokens.set("delete_incident_id", ""); 
        submitted_tokens.set("delete_incident_id", ""); 

        // Reload page to refresh incident list
        setTimeout(function() {
            location.reload();
        }, 1000);
    });
    
    // Handle search errors
    deleteSearchManager.on("search:error", function(properties) {
        console.error("Delete Search Error:", properties);
        alert("Error deleting incident. Check browser console and Splunk logs.");
        $("#delete_incident_btn").prop("disabled", false).text("Permanently Delete Incident " + incident_id);
    });
    
    // Handle search failures
    deleteSearchManager.on("search:fail", function(properties) {
        console.error("Delete Search Failed:", properties);
        alert("Search failed. Check permissions and KVStore configuration.");
        $("#delete_incident_btn").prop("disabled", false).text("Permanently Delete Incident " + incident_id);
    });
});

console.log("Update Incident event handler registered");


    }); // End of $(document).ready
    
}); // End of require
