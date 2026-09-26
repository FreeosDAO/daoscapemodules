#pragma once
#include <eosio/eosio.hpp>
#include <eosio/singleton.hpp>
#include <eosio/crypto.hpp>
#include <eosio/system.hpp>
#include <eosio/transaction.hpp>
#include <algorithm>
namespace pilot {
using namespace eosio;
using std::vector;
using std::string;
inline uint32_t now() { return current_time_point().sec_since_epoch(); }
constexpr uint32_t max_members = 256;
constexpr uint32_t max_candidates = 60;
struct policy {
  bool kyc = false;
  bool normal = false;
  uint32_t applications = 3600, discussion = 3600, ballot = 3600, membervote = 3600, term = 86400;
  EOSLIB_SERIALIZE(policy, (kyc)(normal)(applications)(discussion)(ballot)(membervote)(term))
};
inline policy preset(bool kyc, bool normal) {
  policy p; p.kyc=kyc; p.normal=normal;
  if (normal) { p.applications=172800; p.discussion=172800; p.ballot=86400; p.membervote=259200; p.term=2592000; }
#ifdef PILOT_TEST
  if (!normal) { p.applications=30; p.discussion=10; p.ballot=15; p.membervote=15; p.term=90; }
#endif
  return p;
}
struct [[eosio::table("govconfig"), eosio::contract("daclifycore")]] govconfig {
  name sortition; name membergov; policy rules;
  uint64_t next_snapshot=1;
  EOSLIB_SERIALIZE(govconfig,(sortition)(membergov)(rules)(next_snapshot))
};
using config = singleton<"govconfig"_n,govconfig>;
struct [[eosio::table("govseat"), eosio::contract("daclifycore")]] govseat {
  name holder; uint64_t generation=0; uint64_t cycle=0; uint32_t ends=0; bool recalled=false;
  EOSLIB_SERIALIZE(govseat,(holder)(generation)(cycle)(ends)(recalled))
};
using seat = singleton<"govseat"_n,govseat>;
struct [[eosio::table("govsnaps"), eosio::contract("daclifycore")]] snapshot {
  uint64_t id; name mod_account; uint64_t reference; uint32_t count; uint32_t created; bool kyc;
  uint64_t primary_key()const{return id;}
  EOSLIB_SERIALIZE(snapshot,(id)(mod_account)(reference)(count)(created)(kyc))
};
using snapshots = multi_index<"govsnaps"_n,snapshot>;
struct [[eosio::table("govvoters"), eosio::contract("daclifycore")]] voter {
  name account; uint64_t primary_key()const{return account.value;}
  EOSLIB_SERIALIZE(voter,(account))
};
using voters = multi_index<"govvoters"_n,voter>;
struct [[eosio::table("govprops"), eosio::contract("daclifycore")]] prop {
  uint64_t id; uint64_t primary_key()const{return id;}
  EOSLIB_SERIALIZE(prop,(id))
};
using props = multi_index<"govprops"_n,prop>;
struct [[eosio::table("govapprovals"), eosio::contract("daclifycore")]] approval {
  name account; uint64_t generation; uint64_t primary_key()const{return account.value;}
  EOSLIB_SERIALIZE(approval,(account)(generation))
};
using approvals = multi_index<"govapprovals"_n,approval>;
struct [[eosio::table("govreceipts"), eosio::contract("daclifycore")]] receipt {
  uint64_t id; checksum256 digest; uint32_t executed;
  uint64_t primary_key()const{return id;}
  EOSLIB_SERIALIZE(receipt,(id)(digest)(executed))
};
using receipts = multi_index<"govreceipts"_n,receipt>;
// Prefix-compatible external tables: decode the full deployed member row.
struct member {
  name account; time_point_sec member_since; uint64_t agreed_userterms_version; uint64_t r2;
  uint64_t primary_key()const{return account.value;}
  EOSLIB_SERIALIZE(member,(account)(member_since)(agreed_userterms_version)(r2))
};
using members = multi_index<"members"_n,member>;
struct custodian {
  name account; name authority; uint8_t weight; time_point_sec joined; time_point_sec last_active;
  uint64_t primary_key()const{return account.value;}
  EOSLIB_SERIALIZE(custodian,(account)(authority)(weight)(joined)(last_active))
};
using custodians = multi_index<"custodians"_n,custodian>;
struct kyc_prov {name kyc_provider; string kyc_level; uint64_t kyc_date; EOSLIB_SERIALIZE(kyc_prov,(kyc_provider)(kyc_level)(kyc_date))};
struct userinfo {
  name acc; string username; string avatar; bool verified; uint64_t date; uint64_t verifiedon; name verifier;
  vector<name> raccs; vector<std::tuple<name,name>> aacts; vector<std::tuple<name,string>> ac; vector<kyc_prov> kyc;
  uint64_t primary_key()const{return acc.value;}
  EOSLIB_SERIALIZE(userinfo,(acc)(username)(avatar)(verified)(date)(verifiedon)(verifier)(raccs)(aacts)(ac)(kyc))
};
inline bool kyced(name user) {
  multi_index<"usersinfo"_n,userinfo> t("eosio.proton"_n,"eosio.proton"_n.value);
  auto i=t.find(user.value); if(i==t.end() || !i->verified)return false;
  for(auto &k:i->kyc) if(k.kyc_level.find("firstname")!=string::npos && k.kyc_level.find("lastname")!=string::npos)return true;
  return false;
}
inline bool eligible(name parent,name user,bool kyc) {
  members m(parent,parent.value); return m.find(user.value)!=m.end() && (!kyc || kyced(user));
}
inline bool in_snapshot(name parent,uint64_t id,name user) {voters v(parent,id);return v.find(user.value)!=v.end();}
inline checksum256 action_digest(name parent,uint64_t id,const vector<action>& actions) {
  auto data=pack(std::make_tuple(parent,id,actions));return sha256(data.data(),data.size());
}
inline void bounded_text(const string& value,size_t max,const char* error) {check(!value.empty()&&value.size()<=max,error);}
}
