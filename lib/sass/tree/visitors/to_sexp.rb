require 'sass/util/sexp'

class Sass::Tree::Visitors::ToSexp < Sass::Tree::Visitors::Base
  include Sass::Util::Sexp

  class << self
    def visit(root, options)
      new(options).visit(root)
    end

    def run_callable(name, definition, call, description, visitor)
      capitalized_description = description.capitalize

      if !definition.splat && !call.keywords.empty?
        unknown_args = Sass::Util.array_minus(call.keywords.keys,
          definition.args.map {|var| var.first.underscored_name})
        if definition.splat && unknown_args.include?(definition.splat.underscored_name)
          raise Sass::SyntaxError.new("Argument $#{definition.splat.name} of #{description} " +
            "cannot be used as a named argument.")
        elsif unknown_args.any?
          description = unknown_args.length > 1 ? 'the following arguments:' : 'an argument named'
          raise Sass::SyntaxError.new("#{capitalized_description} doesn't have #{description} " +
            "#{unknown_args.map {|name| "$#{name}"}.join ', '}.")
        end
      end

      if call.args.size > definition.args.size && !definition.splat
        takes = definition.args.size
        passed = call.args.size
        raise Sass::SyntaxError.new("#{capitalized_description} takes #{takes} " +
          "argument#{'s' unless takes == 1} but #{passed} #{passed == 1 ? 'was' : 'were'} passed.")
      end

      block = s(:block)
      if call.kwarg_splat && definition.splat
        kwarg_splat_var = visitor.environment.unique_ident(:kwarg_splat)
        block << s(:lasgn, kwarg_splat_var, call.kwarg_splat.to_sexp(visitor))
        block << s(:if, s(:call, s(:lvar, kwarg_splat_var), :is_a?, sass(:Script, :Value, :Map)),
            nil,
          syntax_error(s(:dstr,
            "Variable keyword arguments must be a map (was ",
            s(:evstr, s(:lvar, kwarg_splat_var)),
            s(:str, ")."))))
      end

      remaining_keywords = call.keywords.dup
      ruby_args = definition.args.zip(call.args[0...definition.args.length])
          .map do |((var, default), value)|
        if value && call.keywords.has_key?(var.name)
          raise Sass::SyntaxError.new("#{capitalized_description} was passed argument " +
            "$#{var.name} both by position and by name.")
        end

        value ||= remaining_keywords.delete(var.name)

        if value.nil?
          unless default
            raise Sass::SyntaxError.new("#{capitalized_description} is missing argument " +
              "#{var.inspect}.")
          end
          s(:nil)
        else
          value.to_sexp(visitor)
        end
      end

      if definition.splat
        if !remaining_keywords.empty?
          map = s(:call, sass(:Util, :NormalizedMap), :new, hash(
              remaining_keywords.as_stored.map do |(name, arg)|
                [s(:str, name), arg.to_sexp(visitor)]
              end))
          if kwarg_splat_var
            map = s(:call, map, :update, s(:call, sass(:Script, :Helpers),
                :arg_hash, s(:lvar, kwarg_splat_var)))
          end
          ruby_args << map
        end

        if call.args.length > definition.args.length
          ruby_args.concat(args[definition.args.length..-1].map {|arg| arg.to_sexp(visitor)})
        end
      end

      if call.splat
        # TODO: if [definition] takes a splat, pass in the original splat's
        # separator and keywords somehow.
        ruby_args << s(:splat, s(:call, call.splat.to_sexp(visitor), :to_a))
      end

      call_sexp = s(:call, s(:ivar, name), :call, *ruby_args)

      if call.has_children
        # Call must be a mixin call, so visitor will have been passed.
        call_sexp = s(:iter, call_sexp, s(:args),
          visitor.with_trace('@content', call) {s(:block, visitor.visit_children(call))})
      end

      block << call_sexp
      visitor.line_info(call, block)
    end
  end

  def initialize(options)
    @imports = {}
    @importer_vars = Sass::Util.to_hash(
      Sass::Util.enum_with_index(options[:load_paths]).map do |(importer, i)|
        [importer, :"@_s_importer_0#{i}"]
      end)
    @root = s(:block)
  end

  attr_reader :root

  public :visit

  def visit_children(parent)
    # Make sure the environment knows about all definitions defined at this
    # scope. That way nested references to those definitions will refer to the
    # correct referents.
    parent.children.each do |child|
      case child
      when Sass::Tree::VariableNode
        unless child.global || @environment.var_variable(child.name)
          @environment.declare_var(child.name)
        end
      when Sass::Tree::FunctionNode
        @environment.declare_fn(child.name, child)
      end
    end

    s(:block, *super)
  end

  def with_parent(name)
    old_env, @environment = @environment, Sass::Environment.new(@environment)
    old_parent_var, @parent_var = @parent_var, name
    old_env_var = @environment.unique_ident(:old_env)
    s(:block,
      s(:lasgn, old_env_var, s(:lvar, :_s_env)),
      s(:lasgn, :_s_env, s(:call, sass(:Environment), :new, s(:lvar, :_s_env))),
      yield,
      s(:lasgn, :_s_env, s(:lvar, old_env_var)))
  ensure
    @parent_var = old_parent_var
    @environment = old_env
  end

  def with_environment(environment)
    old_env, @environment = @environment, environment
    yield
  ensure
    @environment = old_env
  end

  def visit_root(node)
    method_name = @imports[node.filename] = :_s_entrypoint
    defn = s(:defn, method_name, s(:args, :_s_env))
    @importer_vars.map do |(importer, ident)|
      defn << s(:iasgn, ident,
        s(:call, s(:const, :Marshal), :load, s(:str, Marshal.dump(importer))))
    end
    defn <<
      s(:lasgn, :_s_importer, s(:ivar, @importer_vars[node.options[:importer]])) <<
      s(:lasgn, :_s_root, s(:call, sass(:Tree, :RootNode), :new, s(:str, ''))) <<
      with_parent("_s_root") {yield} <<
      s(:lvar, :_s_root)
    @root << line_info(node, defn, :file => node.filename, :name => :nil)
  end

  def visit_comment(node)
    return s(:block) if node.invisible?
    add_node(
      s(:call, sass(:Tree, :CommentNode), :resolved,
        interp_no_strip(node.value),
        s(:lit, node.type),
        node.source_range.to_sexp))
  end

  def visit_debug(node)
    value_var = @environment.unique_ident(:value)
    prefix = node.filename ? "#{node.filename}:#{node.line}" : "Line #{node.line}"
    s(:block,
      s(:lasgn, value_var, node.expr.to_sexp(self)),
      s(:call, sass(:Util), :sass_warn,
        s(:dstr, "#{prefix} DEBUG: ", s(:evstr,
          s(:if, s(:call, s(:lvar, value_var), :is_a?, sass(:Script, :Value, :String)),
              s(:call, s(:lvar, value_var), :value),
            s(:call, s(:lvar, value_var), :to_sass))))))
  end

  def visit_error(node)
    value_var = @environment.unique_ident(:value)
    line_info(node, s(:block,
      s(:lasgn, value_var, node.expr.to_sexp(self)),
      sass_error(s(:if, s(:call, s(:lvar, value_var), :is_a?, sass(:Script, :Value, :String)),
          s(:call, s(:lvar, value_var), :value),
        s(:call, s(:lvar, value_var), :to_sass)))))
  end

  def visit_each(node)
    with_environment Sass::SemiGlobalEnvironment.new(@environment) do
      if node.vars.length == 1
        iter_var = @environment.declare_var(node.vars.first)
        each(s(:call, node.list.to_sexp(node), :to_a), iter_var, yield)
      else
        iter_var = @environment.unique_ident(:iter)
        iter_vars = node.vars.map {|v| @environment.declare_var(v)}
        each(s(:call, node.list.to_sexp(node), :to_a), iter_var,
          s(:masgn, s(:array, *iter_vars.map {|v| s(:lasgn, v)}),
            s(:to_ary, s(:call, s(:lvar, iter_var), :to_a))),
          yield)
      end
    end
  end

  def visit_extend(node)
    line_info(node, add_node(
      s(:call, sass(:Tree, :ExtendNode), :resolved,
        parse(node, node.selector, :parse_selector),
        lit(node.optional?),
        node.source_range.to_sexp,
        node.selector_source_range.to_sexp)))
  end

  def visit_for(node)
    line_info(node, with_environment(Sass::SemiGlobalEnvironment.new(@environment)) do
      from_var = @environment.unique_ident(:from)
      to_var = @environment.unique_ident(:to)
      direction_var = @environment.unique_ident(:direction)
      iter_var = @environment.declare_var(node.var)

      # TODO: This is ripe for optimization. If from and to are static integers,
      # we can generate much simpler code.
      s(:block,
        s(:lasgn, from_var, node.from.to_sexp(self)),
        s(:lasgn, to_var, node.to.to_sexp(self)),
        s(:call, s(:lvar, from_var), :assert_int!),
        s(:call, s(:lvar, to_var), :assert_int!),
        s(:lasgn, to_var, s(:call, s(:lvar, to_var), :coerce,
                            s(:call, s(:lvar, from_var), :numerator_units),
                            s(:call, s(:lvar, from_var), :denominator_units))),
        s(:lasgn, direction_var, s(:if, s(:call, s(:call, s(:lvar, from_var), :to_i), :>,
                                                 s(:call, s(:lvar, to_var), :to_i)),
                                   s(:lit, -1), s(:lit, 1))),
        each(s(:call, s(:const, :Range), :new,
                   s(:call, s(:lvar, :direction_var), :*, s(:call, s(:lvar, from_var), :to_i)),
                   s(:call, s(:lvar, :direction_var), :*, s(:call, s(:lvar, to_var), :to_i)),
                   lit(node.exclusive)),
            iter_var,
          s(:lasgn, iter_var, s(:call, sass(:Script, :Value, :Number), :new,
                                s(:call, s(:lvar, direction_var), :*, s(:lvar, iter_var)),
                                s(:call, s(:lvar, from_var), :numerator_units),
                                s(:call, s(:lvar, from_var), :denominator_units))),
          s(:block, yield)))
    end)
  end

  def visit_function(node)
    declare_callable(@environment.declare_fn(node.name, node), node) do
      s(:iter, s(:call, nil, :catch, s(:lit, :_s_return)), s(:args),
        s(:block,
          body,
          sass_error(s(:str, "Function #{node.name} finished without @return"))))
    end
  end

  def visit_if(node)
    with_environment Sass::SemiGlobalEnvironment.new(@environment) do
      return s(:block, yield) if node.expr.nil?
      s(:if, s(:call, node.expr.to_sexp(self), :to_bool),
          s(:block, yield),
        (visit(node.else) if node.else))
    end
  end

  def visit_import(node)
    if (path = node.css_import?)
      return add_node(
        s(:call, sass(:Tree, :CssImportNode), :resolved,
          s(:str, "url(#{path})"),
          node.source_range.to_sexp))
    end

    # TODO: Handle import loops.
    # Longer-term TODO: Under --watch, only re-eval these methods when the files
    # change.
    file = node.imported_file
    filename = file.options[:filename]
    unless (method_name = @imports[filename])
      method_name = @imports[filename] = @environment.unique_ident("import_#{filename}")
      root = file.to_tree
      Sass::Tree::Visitors::CheckNesting.visit(root)
      @root << node_info(root, s(:defn, method_name, s(:args, @parent_var, :_s_env),
          s(:lasgn, :_s_importer, s(:ivar, @importer_vars[file.options[:importer]])),
          yield),
        :file => filename, :name => :nil)
    end

    line_info(node, s(:call, s(:self), method_name, s(:lvar, @parent_var), s(:lvar, :_s_env)))
  end

  def visit_mixindef(node)
    declare_callable(@environment.declare_mx(node.name, node), node) do
      with_trace(node.name, node) {yield}
    end
  end

  def visit_mixin(node)
    variable, mixin = @environment.mx_variable(node.name)
    add_node(Sass::Tree::Visitors::ToSexp.run_callable(
      variable, mixin, node, "mixin #{mixin.name}", self))
  end

  def visit_content(node)
    s(:if, s(:lvar, @content_var), add_node(s(:call, s(:lvar, @content_var), :call)))
  end

  def visit_prop(node)
    node_sexp = s(:call, sass(:Tree, :PropNode), :resolved,
      interp(node.name),
      s(:call, node.value.to_sexp(self), :to_s),
      node.source_range.to_sexp,
      node.name_source_range.to_sexp,
      node.value_source_range.to_sexp)

    return add_node(node_sexp) unless node.has_children

    prop_var = @environment.unique_ident(:prop)
    s(:block,
      add_node(s(:lasgn, prop_var, node_sexp)),
      with_parent(prop_var) {yield})
  end

  def visit_return(node)
    s(:call, nil, :throw, s(:lit, :_s_return), node.expr.to_sexp(self))
  end

  def visit_rule(node)
    parser_var = @environment.unique_ident(:parser)
    selector_var = @environment.unique_ident(:selector)
    rule_var = @environment.unique_ident(:rule)
    line_info(node, let(:@_s_at_rule_without_rule, s(:false)) do |old_at_rule_without_rule_var|
      s(:block,
        add_node(s(:lasgn, rule_var,
          s(:call, sass(:Tree, :RuleNode), :resolved,
            s(:call, parse(node, node.rule, :parse_selector), :resolve_parent_refs,
              s(:call, s(:lvar, :_s_env), :selector),
              s(:call, s(:lvar, old_at_rule_without_rule_var), :!)),
            node.source_range.to_sexp,
            node.selector_source_range.to_sexp))),
        with_parent(rule_var) do
          s(:block,
            s(:attrasgn, s(:lvar, :_s_env), :selector=,
              s(:call, s(:lvar, rule_var), :resolved_rules)),
            yield)
        end)
    end)
  end

  def visit_atroot(node)
    block = s(:block)

    if node.query
      resolved_type_var = @environment.unique_ident(:resolved_type)
      resolved_value_var = @environment.unique_ident(:resolved_value)
      block << s(:masgn,
        s(:array, s(:lasgn, resolved_type_var), s(:lasgn, resolved_value_var)),
        s(:to_ary, parse(node, node.query, :parse_static_at_root_query)))
      resolved_type = s(:lvar, resolved_type_var)
      resolved_value = s(:lvar, resolved_value_var)
    else
      resolved_type = s(:lit, :without)
      resolved_value = s(:array, s(:str, "rule"))
    end

    old_at_root_without_rule_var = @environment.unique_ident(:old_at_root_without_rule)
    at_root_var = @environment.unique_ident(:at_root)
    block << add_node(s(:lasgn, at_root_var,
        s(:call, sass(:Tree, :AtRootNode), :resolved, resolved_type, resolved_value)))
    block << let(
      :@_s_at_rule_without_rule, s(:call, s(:lvar, at_root_var), :exclude?, s(:str, 'rule'))) do
      with_parent(at_root_var) {yield}
    end
    block
  end

  def visit_variable(node)
    old_var_var = @environment.var_variable(node.name)
    var_var = old_var_var ||
      if node.global
        @environment.declare_global_var(node.name)
      else
        @environment.declare_var(node.name)
      end

    sexp = asgn(var_var, node.expr.to_sexp(self))
    return sexp unless node.guarded && old_var_var

    s(:if, s(:call, var(var_var), :null?), sexp)
  end

  def visit_warn(node)
    value_var = @environment.unique_ident(:value)
    line_info(node, s(:block,
      s(:lasgn, value_var, node.expr.to_sexp(self)),
      s(:call, sass(:Util), :sass_warn,
        s(:dstr, "WARNING: ", s(:evstr, s(:lvar, value_var)), s(:str, "\n         "),
                 s(:evstr, s(:call, chain(s(:lvar, :_s_env), :stack, :to_s), :gsub,
                             s(:str, "\n"), s(:str, "\n         "))),
                 s(:str, "\n")))))
  end

  def visit_while(node)
    with_environment Sass::SemiGlobalEnvironment.new(@environment) do
      s(:while, s(:call, node.expr.to_sexp(self), :to_bool), yield, true)
    end
  end

  def visit_directive(node)
    directive_var = @environment.unique_ident(:directive)
    s(:block,
      add_node(s(:lasgn, directive_var,
          s(:call, sass(:Tree, :DirectiveNode), :resolved, interp(node.value)))),
      with_parent(directive_var) {yield})
  end

  def visit_media(node)
    media_var = @environment.unique_ident(:media)
    s(:block,
      add_node(s(:lasgn, media_var, s(:call, sass(:Tree, :MediaNode), :resolved,
                                      parse(node, node.query, :parse_media_query_list)))),
      with_parent(media_var) {yield})
  end

  def visit_supports(node)
    supports_var = @environment.unique_ident(:supports)
    s(:block,
      add_node(s(:lasgn, supports_var, s(:call, sass(:Tree, :SupportsNode), :resolved,
                                         s(:str, node.name),
                                         node.condition.to_sexp(self)))),
      with_parent(supports_var) {yield})
  end

  def visit_cssimport(node)
    add_node(s(:call, sass(:Tree, :CssImportNode), :resolved,
      interp([node.uri]),
      (parse(node, node.query, :parse_media_query_list) if node.query && !node.query.empty?)))
  end

  def declare_callable(name, node)
    with_parent(nil) do
      args = s(:args, *node.args.map do |(arg, default)|
        arg_name = @environment.declare_var(arg.name)
        next arg_name.to_sym unless default
        s(:lasgn, arg_name, s(:nil))
      end)

      if node.splat
        splat_arg = @environment.declare_var(node.splat.name)
        args << :"*#{splat_arg}"
      end

      if node.is_a?(Sass::Tree::MixinDefNode) && node.has_content
        @content_var = @environment.unique_ident(:content)
        args << :"&#{@content_var}"
      end

      body = s(:block)
      node.args.each do |(arg, default)|
        next unless default
        block << or_asgn(@environment.var_variable(arg.name), default.to_sexp(self))
      end
      if node.splat
        body << s(:lasgn, splat_arg,
          s(:call, sass(:Script, :Value, :ArgList), :new, s(:lvar, splat_var)))
      end
      body << yield

      line_info(node,
        s(:iasgn, name, s(:iter, s(:call, nil, :lambda), args, body)),
        :type => node.is_a?(Sass::Tree::MixinDefNode) ? :mixin : :function,
        :name => node.name)
    end
  ensure
    @content_var = nil
  end

  def interp(script)
    s(:dstr, '', *script.map do |e|
      next s(:str, e) if e.is_a?(String)
      s(:evstr, s(:call, e.to_sexp(self), :to_s,
                  s(:hash, s(:lit, :quote), s(:lit, :none))))
    end)
  end

  def add_node(sexp)
    s(:call, s(:lvar, @parent_var), :<<, sexp)
  end

  def with_trace(name, node)
    trace_var = @environment.unique_ident(:trace)
    s(:block,
      s(:lasgn, trace_var, s(:call, sass(:Tree, :TraceNode), :new, s(:str, name))),
      s(:attrasgn, s(:lvar, trace_var), :line=, s(:lit, node.line)),
      s(:attrasgn, s(:lvar, trace_var), :filename=, s(:str, node.filename)),
      with_parent(trace_var) {yield},
      s(:lvar, trace_var))
  end

  def parse(node, value, method)
    line_info(node,
      s(:call, s(:call, sass(:SCSS, :StaticParser), :new,
                 interp(value),
                 s(:str, node.filename),
                 s(:lvar, :_s_importer),
                 s(:lit, node.line)),
        method))
  end

  def let(var, value)
    old_var = @environment.unique_ident("old_#{var.to_s.gsub(/^@?(_s_)?/, '')}")
    s(:block,
      s(:lasgn, old_var, var(var)),
      asgn(var, value),
      yield(old_var),
      asgn(var, s(:lvar, old_var)))
  end

  def line_info(node, sexp, metadata = {})
    metadata = metadata.merge({:line => node.line})
    s(:block,
      s(:comment, "\n#-s- " + metadata.map {|(k, v)| "#{k}: #{v}"}.join(', ')),
      sexp)
  end
end
