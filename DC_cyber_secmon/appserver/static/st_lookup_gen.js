require([
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/searchmanager',
    'splunkjs/mvc/simplexml/ready!'
], function($, mvc, SearchManager) {
    
    // Listen for button click
    $('#refresh-lookup-btn').on('click', function() {
        
        // Show processing message
        $('#status-message').css({
            'background-color': '#3863A0',
            'color': 'white',
            'display': 'block'
        });
        $('#status-text').text('⏳ Running inventory scan...');
        
        // Disable button during processing
        $('#refresh-lookup-btn').prop('disabled', true);
        
        // Create the search with unique ID
        var searchId = 'inventory_search_' + Date.now();
        var inventorySearch = new SearchManager({
            id: searchId,
            search: '| tstats count, latest(_time) as latest_time where index=* by index, sourcetype | eval latest_time=strftime(latest_time, "%d-%m-%Y %H:%M:%S") | eval age_minutes=round((now()-latest_time)/60, 2) | outputlookup datasource_inventory.csv',
            earliest_time: '0',
            latest_time: 'now',
            autostart: true
        });
        
        // Handle search completion
        inventorySearch.on('search:done', function(properties) {
            $('#status-message').css('background-color', '#5CB85C');
            $('#status-text').text('✓ Datasource inventory updated successfully at ' + new Date().toLocaleTimeString('en-GB'));
            
            // Re-enable button
            $('#refresh-lookup-btn').prop('disabled', false);
            
            // Refresh the dashboard panels after 2 seconds
            setTimeout(function() {
                // Refresh all searches on the dashboard
                var searches = mvc.Components.getInstances().filter(function(c) {
                    return c.name === 'splunk.search';
                });
                searches.forEach(function(search) {
                    search.startSearch();
                });
                
                // Clean up the search manager
                mvc.Components.revokeInstance(searchId);
            }, 2000);
        });
        
        // Handle search failure
        inventorySearch.on('search:error', function(properties) {
            var errorMsg = 'Unknown error';
            if (properties.content && properties.content.messages && properties.content.messages.length > 0) {
                errorMsg = properties.content.messages[0].text;
            }
            $('#status-message').css('background-color', '#DC4E41');
            $('#status-text').text('✗ Error updating inventory: ' + errorMsg);
            
            // Re-enable button
            $('#refresh-lookup-btn').prop('disabled', false);
            
            // Clean up
            mvc.Components.revokeInstance(searchId);
        });
    });

    // Listen for the new button click for sourcetype state
    $('#refresh-sourcetype-btn').on('click', function() {
        
        // Show processing message for sourcetype state
        $('#sourcetype-status-message').css({
            'background-color': '#3863A0',
            'color': 'white',
            'display': 'block'
        });
        $('#sourcetype-status-text').text('⏳ Running sourcetype state scan...');
        
        // Disable button during processing
        $('#refresh-sourcetype-btn').prop('disabled', true);
        
        // Create the search with unique ID
        var sourcetypeSearchId = 'sourcetype_state_search_' + Date.now();
        var sourcetypeSearch = new SearchManager({
            id: sourcetypeSearchId,
            search: '| tstats count WHERE index=* earliest=-7d latest=now BY sourcetype | eval state="initial" | outputlookup sourcetype_state.csv',
            earliest_time: '-7d', // As specified in the SPL
            latest_time: 'now',
            autostart: true
        });
        
        // Handle search completion
        sourcetypeSearch.on('search:done', function(properties) {
            $('#sourcetype-status-message').css('background-color', '#5CB85C');
            $('#sourcetype-status-text').text('✓ Sourcetype state updated successfully at ' + new Date().toLocaleTimeString('en-GB'));
            
            // Re-enable button
            $('#refresh-sourcetype-btn').prop('disabled', false);
            
            // Refresh the dashboard panels after 2 seconds
            setTimeout(function() {
                // Refresh all searches on the dashboard
                var searches = mvc.Components.getInstances().filter(function(c) {
                    return c.name === 'splunk.search';
                });
                searches.forEach(function(search) {
                    search.startSearch();
                });
                
                // Clean up the search manager
                mvc.Components.revokeInstance(sourcetypeSearchId);
            }, 2000);
        });
        
        // Handle search failure
        sourcetypeSearch.on('search:error', function(properties) {
            var errorMsg = 'Unknown error';
            if (properties.content && properties.content.messages && properties.content.messages.length > 0) {
                errorMsg = properties.content.messages[0].text;
            }
            $('#sourcetype-status-message').css('background-color', '#DC4E41');
            $('#sourcetype-status-text').text('✗ Error updating sourcetype state: ' + errorMsg);
            
            // Re-enable button
            $('#refresh-sourcetype-btn').prop('disabled', false);
            
            // Clean up
            mvc.Components.revokeInstance(sourcetypeSearchId);
        });
    });
});

