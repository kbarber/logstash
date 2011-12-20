require "logstash/filters/base"
require "logstash/namespace"
require "logstash/event"

# Esper EPL log correlation filter
class LogStash::Filters::Esper < LogStash::Filters::Base

  config_name "esper"

  # This is an EPL expression that will be used to match the event.
  config :expression, :validate => :string

  public
  def register
    # Get service provider and configuration
    ep_providermanager = com.espertech.esper.client.EPServiceProviderManager
    @ep_service = ep_providermanager.getDefaultProvider
    ep_config = @ep_service.getEPAdministrator.getConfiguration

    # Register event type
    ep_config.addEventType("event", {
         "@source" => "string",
           "@type" => "string",
           "@tags" => "string",
         "@fields" => {},
      "@timestamp" => "string",
    "@source_host" => "string",
    "@source_path" => "string",
        "@message" => "string",
    })
#    ep_config.addEventType("event", {})

    # Create epl statement from expression
    @ep_statement = @ep_service.getEPAdministrator.createEPL(@expression)
  end # def register

  public
  def filter(event)
    if event.type != @type
      @logger.warn("esper: skipping non-matching event type", :type =>
        event.type, :wanted_type => @type, :event => event)
      return
    end

    @logger.warn("Running esper filter", :event => event, :config => config)

    # Process event
    epr_runtime = @ep_service.getEPRuntime
    epr_runtime.sendEvent(event.to_hash, "event")

    event_iterator = @ep_statement.safeIterator

    begin
      if event_iterator.hasNext then
        event_result_item = event_iterator.next

        @logger.warn("event item is: " + event_result_item.getClass.getName)
        case event_result_item.getClass.getName
        when "com.espertech.esper.event.WrapperEventBean"
          # TDOO: this occurs when you use a wildcard and another clause
          # TODO: need to merge the new properties and underlying ones
          @logger.warn("Decorating properties", :properties =>
            event_result_item.getDecoratingProperties)
          event_result_item = event_result_item.getUnderlyingEvent
        end

        event_hash = event_result_item.getProperties.to_hash.clone

        # Cleanup hash then turn it back into a logstash event while preserving
        # type
        event_hash = clean_escapes(event_hash)
        new_event = LogStash::Event.new(event_hash)
        #old_type = event["@type"]
        event.overwrite(new_event)

        # Apply tags and fields after match
        filter_matched(event)
      end

      while(event_iterator.hasNext) do
        # TODO: this is really where we should yield multiple events (like split)
        @logger.warn("iterator not empty - flushing")
        event_iterator.next
      end
    ensure
      event_iterator.close
    end

    @logger.warn("Event after esper filter", :event => event)
  end # def filter

  # Sample code for multi-yield
#  def filter(event)
#    return unless event.type == @type or @type.nil?
#    original_value = event["@message"]
#    original_value = original_value.first if original_value.is_a?(Array)
#    splits = original_value.split(":", -1)
#
#    event["@tags"].each { |tag| 
#      next if !@add_tag.is_a?(Array)
#      return if @add_tag.include?(tag) 
#    }
##    return if splits.length == 1
#
#    splits.each do |value|
#      @logger.warn("foo: #{value}")
#      next if value.empty?
#
#      event_split = event.clone
#      event_split["@message"] = "bleah"
#      filter_matched(event_split)
#
#      yield event_split
#    end
#
#    event.cancel
#  end # def filter

  # Because the select foo as `bar` clause leaves the quotes around, we need to
  # strip them ourselves.
  # TODO: only do this for first and last characters
  def clean_escapes(old_hash)
    new_hash = {}
    old_hash.each do |k,v|
      new = k.gsub('`','')
      new_hash[new] = v
    end
    new_hash
  end # def clean_escapes
end # class LogStash::Filters::Esper
