#include "../../pilot/include/pilot.hpp"
using namespace eosio;
using std::string;using std::vector;
CONTRACT membergov : public contract {
public:
 using contract::contract;
 TABLE settings {name parent;}; using settings_table=singleton<"settings"_n,settings>;
 TABLE state {uint64_t next_id=1;uint64_t active_recall=0;uint32_t recall_after=0;uint32_t active_count=0;};using state_table=singleton<"state"_n,state>;
 // phase: 0 snapshot, 1 petition, 2 ballot, 3 approved, 4 rejected, 5 executed.
 TABLE ballot {
  uint64_t id;name proposer;string title;string reason;checksum256 digest;string payload;
  bool recall=false;uint64_t generation=0;uint64_t snapshot=0;uint32_t electorate=0;
  uint8_t phase=0;uint32_t closes=0;uint32_t expires=0;uint32_t duration=0;
  uint32_t yes=0;uint32_t no=0;uint32_t supporters=0;bool kyc=false;
  uint64_t primary_key()const{return id;}
 };using ballots_table=multi_index<"ballots"_n,ballot>;
 TABLE vote_record {name account;bool yes;uint64_t primary_key()const{return account.value;}};using votes_table=multi_index<"votes"_n,vote_record>;
 TABLE support_record {name account;uint64_t primary_key()const{return account.value;}};using supports_table=multi_index<"supporters"_n,support_record>;
 TABLE open_record {name proposer;uint64_t id;uint64_t primary_key()const{return proposer.value;}};using opens_table=multi_index<"openballots"_n,open_record>;
 name parent()const{return settings_table(get_self(),get_self().value).get().parent;}
 ACTION init(name parent) {require_auth(get_self());check(is_account(parent)&&parent!=get_self(),"Invalid parent");settings_table t(get_self(),get_self().value);check(!t.exists(),"Already initialized");t.set({parent},get_self());}
 ACTION propose(name proposer,uint64_t id,string title,string reason,checksum256 digest,string payload) {check(payload.size()<=8192,"Payload preview exceeds 8192 bytes");open(proposer,id,title,reason,digest,false,payload);}
 ACTION petition(name proposer,uint64_t id,string reason) {open(proposer,id,"Recall elected guardian",reason,checksum256{},true,"");}
 void open(name proposer,uint64_t id,string title,string reason,checksum256 digest,bool recall,string payload) {
  require_auth(proposer);auto p=parent();auto cfg=pilot::config(p,p.value).get();check(cfg.membergov==get_self(),"Module not active");
  check(pilot::eligible(p,proposer,cfg.rules.kyc),"Not an eligible member");
  pilot::bounded_text(title,120,"Title must be 1–120 bytes");pilot::bounded_text(reason,4096,"Reason must be 1–4096 bytes");
  state_table st(get_self(),get_self().value);auto s=st.get_or_default();check(id==s.next_id,"Ballot ID changed; refresh and retry");check(s.active_count<16,"At most 16 active ballots");
  opens_table o(get_self(),get_self().value);check(o.find(proposer.value)==o.end(),"Finish your existing ballot first");
  uint64_t gen=0;
  if(recall){auto seat=pilot::seat(p,p.value).get();check(seat.holder.value&&!seat.recalled&&pilot::now()<seat.ends,"No active elected guardian");check(!s.active_recall&&pilot::now()>=s.recall_after,"Recall active or cooling down");gen=seat.generation;s.active_recall=id;}
  ++s.next_id;++s.active_count;st.set(s,get_self());o.emplace(get_self(),[&](auto&r){r.proposer=proposer;r.id=id;});
  ballots_table t(get_self(),get_self().value);t.emplace(get_self(),[&](auto&r){r.id=id;r.proposer=proposer;r.title=title;r.reason=reason;r.digest=digest;r.payload=payload;r.recall=recall;r.generation=gen;r.duration=cfg.rules.membervote;r.kyc=cfg.rules.kyc;});
  action(permission_level{get_self(),"active"_n},p,"makesnap"_n,std::make_tuple(get_self(),id,cfg.rules.kyc)).send();
 }
 ACTION snapready(uint64_t reference,uint64_t snapshot,uint32_t count) {
  require_auth(parent());ballots_table t(get_self(),get_self().value);auto i=t.require_find(reference,"Unknown ballot");check(i->phase==0,"Snapshot already assigned");
  check(pilot::in_snapshot(parent(),snapshot,i->proposer),"Proposer missing from electorate");
  t.modify(i,same_payer,[&](auto&r){r.snapshot=snapshot;r.electorate=count;r.phase=r.recall?1:2;r.closes=pilot::now()+r.duration;});
  if(i->recall)add_support(reference,i->proposer);
 }
 void add_support(uint64_t id,name account) {
  ballots_table t(get_self(),get_self().value);auto i=t.require_find(id,"Unknown petition");supports_table supports(get_self(),id);
  check(supports.find(account.value)==supports.end(),"Already supported");supports.emplace(get_self(),[&](auto&r){r.account=account;});
  t.modify(i,same_payer,[&](auto&r){++r.supporters;if(uint64_t(r.supporters)*100>=uint64_t(r.electorate)*10){r.phase=2;r.closes=pilot::now()+r.duration;}});
 }
 ACTION support(name member,uint64_t id) {require_auth(member);ballots_table t(get_self(),get_self().value);auto i=t.require_find(id,"Unknown petition");check(i->phase==1&&pilot::now()<i->closes,"Petition is not open");check(pilot::in_snapshot(parent(),i->snapshot,member),"Not in electorate");add_support(id,member);}
 ACTION vote(name member,uint64_t id,bool yes) {
  require_auth(member);ballots_table t(get_self(),get_self().value);auto i=t.require_find(id,"Unknown ballot");check(i->phase==2&&pilot::now()<i->closes,"Ballot is not open");check(pilot::in_snapshot(parent(),i->snapshot,member),"Not in electorate");
  votes_table v(get_self(),id);auto old=v.find(member.value);bool prior=false,changed=old!=v.end();if(changed)prior=old->yes;
  if(changed)v.modify(old,same_payer,[&](auto&r){r.yes=yes;});else v.emplace(get_self(),[&](auto&r){r.account=member;r.yes=yes;});
  t.modify(i,same_payer,[&](auto&r){if(changed){if(prior)--r.yes;else --r.no;}if(yes)++r.yes;else ++r.no;});
 }
 void close_slot(const ballot& b,bool failed) {
  state_table st(get_self(),get_self().value);auto s=st.get();--s.active_count;
  if(b.recall){s.active_recall=0;if(failed)s.recall_after=pilot::now()+b.duration;}st.set(s,get_self());
  opens_table o(get_self(),get_self().value);auto i=o.find(b.proposer.value);if(i!=o.end()&&i->id==b.id)o.erase(i);
 }
 ACTION finalize(uint64_t id) {
  ballots_table t(get_self(),get_self().value);auto i=t.require_find(id,"Unknown ballot");if(i->phase>=3)return;
  check(i->phase>0&&pilot::now()>=i->closes,"Voting window still open");
  bool passed=i->phase==2 && uint64_t(i->yes+i->no)*100>=uint64_t(i->electorate)*30 && i->yes>i->no;
  if(i->recall){auto s=pilot::seat(parent(),parent().value).get_or_default();if(s.generation!=i->generation||s.recalled||pilot::now()>=s.ends)passed=false;}
  auto copy=*i;close_slot(copy,!passed);
  t.modify(i,same_payer,[&](auto&r){r.phase=passed?(r.recall?5:3):4;r.expires=r.closes+r.duration;});
  if(passed&&copy.recall) action(permission_level{get_self(),"active"_n},parent(),"revokeseat"_n,std::make_tuple(copy.generation)).send();
 }
 ACTION execute(uint64_t id,vector<action> actions) {
  ballots_table t(get_self(),get_self().value);auto i=t.require_find(id,"Unknown ballot");
  check(i->phase==3&&!i->recall&&pilot::now()<i->expires,"Ballot not approved, expired or already executed");
  check(pilot::action_digest(parent(),id,actions)==i->digest,"Payload does not match member approval");
  t.modify(i,same_payer,[&](auto&r){r.phase=5;});
  action(permission_level{get_self(),"active"_n},parent(),"memberexec"_n,std::make_tuple(id,actions)).send();
 }
};
