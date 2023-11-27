###################################################
# DCOM parser for Samba
# Basically the glue between COM and DCE/RPC with NDR
# Copyright jelmer@samba.org 2003-2005
# released under the GNU GPL

package Parse::Pidl::Samba4::COM::Proxy;

use Parse::Pidl::Samba4::COM::Header;
use Parse::Pidl::Typelist qw(mapTypeName);
use Parse::Pidl::Util qw(has_property);

use vars qw($VERSION);
$VERSION = '0.01';

use strict;
use warnings;

my($res);

sub ParseVTable($$)
{
	my ($interface, $name) = @_;

	# Generate the vtable
	$res .="\tstruct $interface->{NAME}_vtable $name = {";

	if (defined($interface->{BASE})) {
		$res .= "\n\t\t{},";
	}

	my $data = $interface->{DATA};

	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "FUNCTION") {
		    $res .= "\n\t\tdcom_proxy_$interface->{NAME}_$d->{NAME}";
			$res .= ",";
		}
	}

	$res .= "\n\t};\n\n";
}

sub ParseRegFunc($)
{
	my $interface = shift;

	$res .= "NTSTATUS dcom_proxy_init_$interface->{NAME}(TALLOC_CTX *ctx);\n";
	$res .= "NTSTATUS dcom_proxy_init_$interface->{NAME}(TALLOC_CTX *ctx)
{
	struct $interface->{NAME}_vtable *proxy_vtable = talloc(ctx, struct $interface->{NAME}_vtable);
";

	if (defined($interface->{BASE})) {
		$res.= "
	struct GUID base_iid;
	const void *base_vtable;

	base_iid = ndr_table_$interface->{BASE}.syntax_id.uuid;

	base_vtable = dcom_proxy_vtable_by_iid(&base_iid);
	if (base_vtable == NULL) {
		DEBUG(0, (\"No proxy registered for base interface '$interface->{BASE}'\\n\"));
		return NT_STATUS_FOOBAR;
	}
	
	memcpy(proxy_vtable, base_vtable, sizeof(struct $interface->{BASE}_vtable));

";
	}
	foreach my $x (@{$interface->{DATA}}) {
		next unless ($x->{TYPE} eq "FUNCTION");

		$res .= "\tproxy_vtable->$x->{NAME} = dcom_proxy_$interface->{NAME}_$x->{NAME};\n";
	}

	$res.= "
	proxy_vtable->iid = ndr_table_$interface->{NAME}.syntax_id.uuid;

	return dcom_register_proxy(ctx, (struct IUnknown_vtable *)proxy_vtable);
}\n\n";
}

#####################################################################
# parse a function
sub ParseFunction($$)
{
	my ($interface, $fn) = @_;
	my $name = $fn->{NAME};
	my $uname = uc $name;

	my $tn = mapTypeName($fn->{RETURN_TYPE});

    my $w_error = "NT_STATUS_V(status)";
	if ($fn->{RETURN_TYPE} eq "WERROR") {
		$w_error = "W_ERROR(NT_STATUS_V(status))";
	}
	if ($fn->{RETURN_TYPE} eq "void") {
		$w_error = "";
	}

	$res.="
static $tn dcom_proxy_$interface->{NAME}_$name(struct $interface->{NAME} *d, TALLOC_CTX *mem_ctx" . Parse::Pidl::Samba4::COM::Header::GetArgumentProtoList($fn) . ")
{
	struct dcerpc_binding_handle *h;
	NTSTATUS status = dcom_binding_handle(d->ctx, &d->obj, &d->vtable->iid, &h);
	struct $name r;
	// struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return $w_error;
	}

	NDR_ZERO_STRUCT(r.in);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;
";

	# Put arguments into r
	foreach my $a (@{$fn->{ELEMENTS}}) {
		next unless (has_property($a, "in"));
		if (Parse::Pidl::Typelist::typeIs($a->{TYPE}, "INTERFACE")) {
			if (has_property($a, "out")) {
                $res .= "\tif (*$a->{NAME}) {\n";
				$res .= "\t\tWERROR_CHECK(dcom_OBJREF_from_IUnknown(mem_ctx, &(*(r.in.$a->{NAME}))->obj, (struct IUnknown*)(*$a->{NAME})));\n";
                $res .= "\t}\n";
			} else {
                $res .= "\tif ($a->{NAME}) {\n";
                $res .="\t\tr.in.$a->{NAME} = talloc_zero(mem_ctx, struct MInterfacePointer);\n";
				$res .="\t\tWERROR_CHECK(dcom_OBJREF_from_IUnknown(mem_ctx, &r.in.$a->{NAME}->obj, (struct IUnknown*)$a->{NAME}));\n";
                $res .= "\t}\n";
			}
		} else {
			if (has_property($a, "string")) {
				$res .= "\tr.in.$a->{NAME} = (const char*)$a->{NAME};\n";
			} else {
				$res .= "\tr.in.$a->{NAME} = $a->{NAME};\n";
			}
		}
	}

	$res .="
#if 0
	if (h->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG($name, &r);
	}
#endif
	status = dcerpc_binding_handle_call(h, &d->obj.u_objref.u_standard.std.ipid, &ndr_table_$interface->{NAME}, NDR_$uname, mem_ctx, &r);
    if (NT_STATUS_IS_ERR(status)) {
		return $w_error;
	}
#if 0
	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG($name, &r);
	}
#endif

";

	# Put r info back into arguments
	foreach my $a (@{$fn->{ELEMENTS}}) {
		next unless (has_property($a, "out"));

		if (Parse::Pidl::Typelist::typeIs($a->{TYPE}, "INTERFACE")) {
			$res .="\tWERROR_CHECK(dcom_IUnknown_from_MIP(d->ctx, (struct IUnknown**)$a->{NAME}, *r.out.$a->{NAME}));\n";
		} else {
			$res .= "\t*$a->{NAME} = *r.out.$a->{NAME};\n";
		}

	}
	
	if ($fn->{RETURN_TYPE} eq "NTSTATUS") {
		$res .= "\tif (NT_STATUS_IS_OK(status)) status = r.out.result;\n";
	}

	if ($fn->{RETURN_TYPE} eq "void") {
		$res .=
	"
	return;
}\n\n";
	} else {
	    $res .=
	"
	return r.out.result;
}\n\n";
    }
}

#####################################################################
# parse the interface definitions
sub ParseInterface($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};
	$res = "/* DCOM proxy for $interface->{NAME} generated by pidl */\n\n";
	foreach my $d (@{$data}) {
		($d->{TYPE} eq "FUNCTION") && 
		ParseFunction($interface, $d);
	}

	ParseRegFunc($interface);
}

sub RegistrationFunction($$)
{
	my $idl = shift;
	my $basename = shift;

	my $res = "\n\nNTSTATUS dcom_$basename\_init(void)\n";
	$res .= "{\n";
	$res .="\tNTSTATUS status = NT_STATUS_OK;\n";
	foreach my $interface (@{$idl}) {
		next if $interface->{TYPE} ne "INTERFACE";
		next if not has_property($interface, "object");

		my $data = $interface->{DATA};
		my $count = 0;
		foreach my $d (@{$data}) {
			if ($d->{TYPE} eq "FUNCTION") { $count++; }
		}

		next if ($count == 0);

		$res .= "\tstatus = dcom_$interface->{NAME}_init();\n";
		$res .= "\tif (NT_STATUS_IS_ERR(status)) {\n";
		$res .= "\t\treturn status;\n";
		$res .= "\t}\n\n";
	}
	$res .= "\treturn status;\n";
	$res .= "}\n\n";

	return $res;
}

sub Parse($$)
{
	my ($pidl,$comh_filename) = @_;
	my $res = "";
	my $has_obj = 0;

	$res .=	"#include \"includes.h\"\n" .
			"#include \"lib/com/dcom/dcom.h\"\n" .
			"#include \"$comh_filename\"\n" .
			"#include \"librpc/rpc/dcerpc.h\"\n";

	foreach (@{$pidl}) {
		next if ($_->{TYPE} ne "INTERFACE");
		next if has_property($_, "local");
		next unless has_property($_, "object");

		$res .= ParseInterface($_);

		$has_obj = 1;
	}

	return $res if ($has_obj);
	return undef;
}

1;
