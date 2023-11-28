// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::*;
use asset_hub_rococo_runtime::xcm_config::XcmConfig as AssetHubRococoXcmConfig;
use frame_support::weights::WeightToFee;
use rococo_runtime::xcm_config::XcmConfig as RococoXcmConfig;
use rococo_system_emulated_network::penpal_emulated_chain::{
	ForeignAssetOnAssetHub, LocalTeleportableToAssetHub, XcmConfig as PenpalRococoXcmConfig,
	TELEPORTABLE_ASSET_ID,
};

fn relay_to_para_sender_assertions(t: RelayToParaTest) {
	type RuntimeEvent = <Rococo as Chain>::RuntimeEvent;

	Rococo::assert_xcm_pallet_attempted_complete(Some(Weight::from_parts(864_610_000, 8_799)));

	assert_expected_events!(
		Rococo,
		vec![
			// Amount to reserve transfer is transferred to Parachain's Sovereign account
			RuntimeEvent::Balances(
				pallet_balances::Event::Transfer { from, to, amount }
			) => {
				from: *from == t.sender.account_id,
				to: *to == Rococo::sovereign_account_id_of(
					t.args.dest
				),
				amount: *amount == t.args.amount,
			},
		]
	);
}

fn system_para_to_para_sender_assertions(t: SystemParaToParaTest) {
	type RuntimeEvent = <AssetHubRococo as Chain>::RuntimeEvent;

	AssetHubRococo::assert_xcm_pallet_attempted_complete(Some(Weight::from_parts(
		864_610_000,
		8_799,
	)));

	assert_expected_events!(
		AssetHubRococo,
		vec![
			// Amount to reserve transfer is transferred to Parachain's Sovereign account
			RuntimeEvent::Balances(
				pallet_balances::Event::Transfer { from, to, amount }
			) => {
				from: *from == t.sender.account_id,
				to: *to == AssetHubRococo::sovereign_account_id_of(
					t.args.dest
				),
				amount: *amount == t.args.amount,
			},
		]
	);
}

fn para_receiver_assertions<Test>(_: Test) {
	type RuntimeEvent = <PenpalA as Chain>::RuntimeEvent;
	assert_expected_events!(
		PenpalA,
		vec![
			RuntimeEvent::Balances(pallet_balances::Event::Deposit { .. }) => {},
			RuntimeEvent::MessageQueue(
				pallet_message_queue::Event::Processed { success: true, .. }
			) => {},
		]
	);
}

fn para_to_system_para_sender_assertions(t: ParaToSystemParaTest) {
	type RuntimeEvent = <PenpalA as Chain>::RuntimeEvent;

	PenpalA::assert_xcm_pallet_attempted_complete(Some(Weight::from_parts(864_610_000, 8_799)));

	assert_expected_events!(
		PenpalA,
		vec![
			// Amount to reserve transfer is transferred to Parachain's Sovereign account
			RuntimeEvent::Balances(
				pallet_balances::Event::Withdraw { who, amount }
			) => {
				who: *who == t.sender.account_id,
				amount: *amount == t.args.amount,
			},
		]
	);
}

fn para_to_system_para_receiver_assertions(t: ParaToSystemParaTest) {
	type RuntimeEvent = <AssetHubRococo as Chain>::RuntimeEvent;

	let sov_penpal_on_ahr = AssetHubRococo::sovereign_account_id_of(
		AssetHubRococo::sibling_location_of(PenpalA::para_id()),
	);

	assert_expected_events!(
		AssetHubRococo,
		vec![
			// Amount to reserve transfer is transferred to Parachain's Sovereign account
			RuntimeEvent::Balances(
				pallet_balances::Event::Withdraw { who, amount }
			) => {
				who: *who == sov_penpal_on_ahr.clone().into(),
				amount: *amount == t.args.amount,
			},
			RuntimeEvent::Balances(pallet_balances::Event::Deposit { .. }) => {},
			RuntimeEvent::MessageQueue(
				pallet_message_queue::Event::Processed { success: true, .. }
			) => {},
		]
	);
}

fn system_para_to_para_assets_sender_assertions(t: SystemParaToParaTest) {
	type RuntimeEvent = <AssetHubRococo as Chain>::RuntimeEvent;

	AssetHubRococo::assert_xcm_pallet_attempted_complete(Some(Weight::from_parts(
		864_610_000,
		8799,
	)));

	assert_expected_events!(
		AssetHubRococo,
		vec![
			// Amount to reserve transfer is transferred to Parachain's Sovereign account
			RuntimeEvent::Assets(
				pallet_assets::Event::Transferred { asset_id, from, to, amount }
			) => {
				asset_id: *asset_id == ASSET_ID,
				from: *from == t.sender.account_id,
				to: *to == AssetHubRococo::sovereign_account_id_of(
					t.args.dest
				),
				amount: *amount == t.args.amount,
			},
		]
	);
}

fn system_para_to_para_assets_receiver_assertions<Test>(_: Test) {
	type RuntimeEvent = <PenpalA as Chain>::RuntimeEvent;
	assert_expected_events!(
		PenpalA,
		vec![
			RuntimeEvent::Balances(pallet_balances::Event::Deposit { .. }) => {},
			RuntimeEvent::Assets(pallet_assets::Event::Issued { .. }) => {},
			RuntimeEvent::MessageQueue(
				pallet_message_queue::Event::Processed { success: true, .. }
			) => {},
		]
	);
}

fn relay_to_para_limited_reserve_transfer_assets(t: RelayToParaTest) -> DispatchResult {
	<Rococo as RococoPallet>::XcmPallet::limited_reserve_transfer_assets(
		t.signed_origin,
		bx!(t.args.dest.into()),
		bx!(t.args.beneficiary.into()),
		bx!(t.args.assets.into()),
		t.args.fee_asset_item,
		t.args.weight_limit,
	)
}

fn system_para_to_para_limited_reserve_transfer_assets(t: SystemParaToParaTest) -> DispatchResult {
	<AssetHubRococo as AssetHubRococoPallet>::PolkadotXcm::limited_reserve_transfer_assets(
		t.signed_origin,
		bx!(t.args.dest.into()),
		bx!(t.args.beneficiary.into()),
		bx!(t.args.assets.into()),
		t.args.fee_asset_item,
		t.args.weight_limit,
	)
}

fn para_to_system_para_reserve_transfer_assets(t: ParaToSystemParaTest) -> DispatchResult {
	<PenpalA as PenpalAPallet>::PolkadotXcm::transfer_assets(
		t.signed_origin,
		bx!(t.args.dest.into()),
		bx!(t.args.beneficiary.into()),
		bx!(t.args.assets.into()),
		t.args.fee_asset_item,
		t.args.weight_limit,
	)
}

fn system_para_to_para_transfer_assets(t: SystemParaToParaTest) -> DispatchResult {
	<AssetHubRococo as AssetHubRococoPallet>::PolkadotXcm::transfer_assets(
		t.signed_origin,
		bx!(t.args.dest.into()),
		bx!(t.args.beneficiary.into()),
		bx!(t.args.assets.into()),
		t.args.fee_asset_item,
		t.args.weight_limit,
	)
}

fn para_to_system_para_transfer_assets(t: ParaToSystemParaTest) -> DispatchResult {
	<PenpalA as PenpalAPallet>::PolkadotXcm::transfer_assets(
		t.signed_origin,
		bx!(t.args.dest.into()),
		bx!(t.args.beneficiary.into()),
		bx!(t.args.assets.into()),
		t.args.fee_asset_item,
		t.args.weight_limit,
	)
}

/// Reserve Transfers of native asset from Relay Chain to the System Parachain shouldn't work
#[test]
fn reserve_transfer_native_asset_from_relay_to_system_para_fails() {
	let signed_origin = <Rococo as Chain>::RuntimeOrigin::signed(RococoSender::get().into());
	let destination = Rococo::child_location_of(AssetHubRococo::para_id());
	let beneficiary: MultiLocation =
		AccountId32Junction { network: None, id: AssetHubRococoReceiver::get().into() }.into();
	let amount_to_send: Balance = ROCOCO_ED * 1000;
	let assets: MultiAssets = (Here, amount_to_send).into();
	let fee_asset_item = 0;

	// this should fail
	Rococo::execute_with(|| {
		let result = <Rococo as RococoPallet>::XcmPallet::limited_reserve_transfer_assets(
			signed_origin,
			bx!(destination.into()),
			bx!(beneficiary.into()),
			bx!(assets.into()),
			fee_asset_item,
			WeightLimit::Unlimited,
		);
		assert_err!(
			result,
			DispatchError::Module(sp_runtime::ModuleError {
				index: 99,
				error: [2, 0, 0, 0],
				message: Some("Filtered")
			})
		);
	});
}

/// Reserve Transfers of native asset from System Parachain to Relay Chain shouldn't work
#[test]
fn reserve_transfer_native_asset_from_system_para_to_relay_fails() {
	// Init values for System Parachain
	let signed_origin =
		<AssetHubRococo as Chain>::RuntimeOrigin::signed(AssetHubRococoSender::get().into());
	let destination = AssetHubRococo::parent_location();
	let beneficiary_id = RococoReceiver::get();
	let beneficiary: MultiLocation =
		AccountId32Junction { network: None, id: beneficiary_id.into() }.into();
	let amount_to_send: Balance = ASSET_HUB_ROCOCO_ED * 1000;

	let assets: MultiAssets = (Parent, amount_to_send).into();
	let fee_asset_item = 0;

	// this should fail
	AssetHubRococo::execute_with(|| {
		let result =
			<AssetHubRococo as AssetHubRococoPallet>::PolkadotXcm::limited_reserve_transfer_assets(
				signed_origin,
				bx!(destination.into()),
				bx!(beneficiary.into()),
				bx!(assets.into()),
				fee_asset_item,
				WeightLimit::Unlimited,
			);
		assert_err!(
			result,
			DispatchError::Module(sp_runtime::ModuleError {
				index: 31,
				error: [2, 0, 0, 0],
				message: Some("Filtered")
			})
		);
	});
}

/// Reserve Transfers of native asset from Relay to Parachain should work
#[test]
fn reserve_transfer_native_asset_from_relay_to_para() {
	// Init values for Relay
	let destination = Rococo::child_location_of(PenpalA::para_id());
	let beneficiary_id = PenpalAReceiver::get();
	let amount_to_send: Balance = ROCOCO_ED * 1000;

	let test_args = TestContext {
		sender: RococoSender::get(),
		receiver: PenpalAReceiver::get(),
		args: relay_test_args(destination, beneficiary_id, amount_to_send),
	};

	let mut test = RelayToParaTest::new(test_args);

	let sender_balance_before = test.sender.balance;
	let receiver_balance_before = test.receiver.balance;

	test.set_assertion::<Rococo>(relay_to_para_sender_assertions);
	test.set_assertion::<PenpalA>(para_receiver_assertions);
	test.set_dispatchable::<Rococo>(relay_to_para_limited_reserve_transfer_assets);
	test.assert();

	let delivery_fees = Rococo::execute_with(|| {
		xcm_helpers::transfer_assets_delivery_fees::<
			<RococoXcmConfig as xcm_executor::Config>::XcmSender,
		>(test.args.assets.clone(), 0, test.args.weight_limit, test.args.beneficiary, test.args.dest)
	});

	let sender_balance_after = test.sender.balance;
	let receiver_balance_after = test.receiver.balance;

	// Sender's balance is reduced
	assert_eq!(sender_balance_before - amount_to_send - delivery_fees, sender_balance_after);
	// Receiver's balance is increased
	assert!(receiver_balance_after > receiver_balance_before);
	// Receiver's balance increased by `amount_to_send - delivery_fees - bought_execution`;
	// `delivery_fees` might be paid from transfer or JIT, also `bought_execution` is unknown but
	// should be non-zero
	assert!(receiver_balance_after < receiver_balance_before + amount_to_send);
}

/// Reserve Transfers of native asset from System Parachain to Parachain should work
#[test]
fn reserve_transfer_native_asset_from_system_para_to_para() {
	// Init values for System Parachain
	let destination = AssetHubRococo::sibling_location_of(PenpalA::para_id());
	let beneficiary_id = PenpalAReceiver::get();
	let amount_to_send: Balance = ASSET_HUB_ROCOCO_ED * 1000;
	let assets = (Parent, amount_to_send).into();

	let test_args = TestContext {
		sender: AssetHubRococoSender::get(),
		receiver: PenpalAReceiver::get(),
		args: para_test_args(destination, beneficiary_id, amount_to_send, assets, None, 0),
	};

	let mut test = SystemParaToParaTest::new(test_args);

	let sender_balance_before = test.sender.balance;
	let receiver_balance_before = test.receiver.balance;

	test.set_assertion::<AssetHubRococo>(system_para_to_para_sender_assertions);
	test.set_assertion::<PenpalA>(para_receiver_assertions);
	test.set_dispatchable::<AssetHubRococo>(system_para_to_para_limited_reserve_transfer_assets);
	test.assert();

	let sender_balance_after = test.sender.balance;
	let receiver_balance_after = test.receiver.balance;

	let delivery_fees = AssetHubRococo::execute_with(|| {
		xcm_helpers::transfer_assets_delivery_fees::<
			<AssetHubRococoXcmConfig as xcm_executor::Config>::XcmSender,
		>(test.args.assets.clone(), 0, test.args.weight_limit, test.args.beneficiary, test.args.dest)
	});

	// Sender's balance is reduced
	assert_eq!(sender_balance_before - amount_to_send - delivery_fees, sender_balance_after);
	// Receiver's balance is increased
	assert!(receiver_balance_after > receiver_balance_before);
	// Receiver's balance increased by `amount_to_send - delivery_fees - bought_execution`;
	// `delivery_fees` might be paid from transfer or JIT, also `bought_execution` is unknown but
	// should be non-zero
	assert!(receiver_balance_after < receiver_balance_before + amount_to_send);
}

/// Reserve Transfers of native asset from Parachain to System Parachain should work
#[test]
fn reserve_transfer_native_asset_from_para_to_system_para() {
	// Init values for Penpal Parachain
	let destination = PenpalA::sibling_location_of(AssetHubRococo::para_id());
	let beneficiary_id = AssetHubRococoReceiver::get();
	let amount_to_send: Balance = ASSET_HUB_ROCOCO_ED * 1000;
	let assets = (Parent, amount_to_send).into();

	let test_args = TestContext {
		sender: PenpalASender::get(),
		receiver: AssetHubRococoReceiver::get(),
		args: para_test_args(destination, beneficiary_id, amount_to_send, assets, None, 0),
	};

	let mut test = ParaToSystemParaTest::new(test_args);

	let sender_balance_before = test.sender.balance;
	let receiver_balance_before = test.receiver.balance;

	let penpal_location_as_seen_by_ahr = AssetHubRococo::sibling_location_of(PenpalA::para_id());
	let sov_penpal_on_ahr = AssetHubRococo::sovereign_account_id_of(penpal_location_as_seen_by_ahr);

	// fund the Penpal's SA on AHR with the native tokens held in reserve
	AssetHubRococo::fund_accounts(vec![(sov_penpal_on_ahr.into(), amount_to_send * 2)]);

	test.set_assertion::<PenpalA>(para_to_system_para_sender_assertions);
	test.set_assertion::<AssetHubRococo>(para_to_system_para_receiver_assertions);
	test.set_dispatchable::<PenpalA>(para_to_system_para_reserve_transfer_assets);
	test.assert();

	let sender_balance_after = test.sender.balance;
	let receiver_balance_after = test.receiver.balance;

	let delivery_fees = PenpalA::execute_with(|| {
		xcm_helpers::transfer_assets_delivery_fees::<
			<PenpalRococoXcmConfig as xcm_executor::Config>::XcmSender,
		>(test.args.assets.clone(), 0, test.args.weight_limit, test.args.beneficiary, test.args.dest)
	});

	// Sender's balance is reduced
	assert_eq!(sender_balance_before - amount_to_send - delivery_fees, sender_balance_after);
	// Receiver's balance is increased
	assert!(receiver_balance_after > receiver_balance_before);
	// Receiver's balance increased by `amount_to_send - delivery_fees - bought_execution`;
	// `delivery_fees` might be paid from transfer or JIT, also `bought_execution` is unknown but
	// should be non-zero
	assert!(receiver_balance_after < receiver_balance_before + amount_to_send);
}

/// Reserve Transfers of a local asset and native asset from System Parachain to Parachain should
/// work
#[test]
fn reserve_transfer_assets_from_system_para_to_para() {
	// Force create asset on AssetHubRococo and PenpalA from Relay Chain
	AssetHubRococo::force_create_and_mint_asset(
		ASSET_ID,
		ASSET_MIN_BALANCE,
		false,
		AssetHubRococoSender::get(),
		Some(Weight::from_parts(1_019_445_000, 200_000)),
		ASSET_MIN_BALANCE * 1_000_000,
	);
	PenpalA::force_create_and_mint_asset(
		ASSET_ID,
		ASSET_MIN_BALANCE,
		false,
		PenpalASender::get(),
		None,
		0,
	);

	// Init values for System Parachain
	let destination = AssetHubRococo::sibling_location_of(PenpalA::para_id());
	let beneficiary_id = PenpalAReceiver::get();
	let fee_amount_to_send = ASSET_HUB_ROCOCO_ED * 1000;
	let asset_amount_to_send = ASSET_MIN_BALANCE * 1000;
	let assets: MultiAssets = vec![
		(Parent, fee_amount_to_send).into(),
		(X2(PalletInstance(ASSETS_PALLET_ID), GeneralIndex(ASSET_ID.into())), asset_amount_to_send)
			.into(),
	]
	.into();
	let fee_asset_index = assets
		.inner()
		.iter()
		.position(|r| r == &(Parent, fee_amount_to_send).into())
		.unwrap() as u32;

	let para_test_args = TestContext {
		sender: AssetHubRococoSender::get(),
		receiver: PenpalAReceiver::get(),
		args: para_test_args(
			destination,
			beneficiary_id,
			asset_amount_to_send,
			assets,
			None,
			fee_asset_index,
		),
	};

	let mut test = SystemParaToParaTest::new(para_test_args);

	// Create SA-of-Penpal-on-AHR with ED.
	let penpal_location = AssetHubRococo::sibling_location_of(PenpalA::para_id());
	let sov_penpal_on_ahr = AssetHubRococo::sovereign_account_id_of(penpal_location);
	AssetHubRococo::fund_accounts(vec![(sov_penpal_on_ahr.into(), ROCOCO_ED)]);

	let sender_balance_before = test.sender.balance;
	let receiver_balance_before = test.receiver.balance;

	let sender_assets_before = AssetHubRococo::execute_with(|| {
		type Assets = <AssetHubRococo as AssetHubRococoPallet>::Assets;
		<Assets as Inspect<_>>::balance(ASSET_ID, &AssetHubRococoSender::get())
	});
	let receiver_assets_before = PenpalA::execute_with(|| {
		type Assets = <PenpalA as PenpalAPallet>::Assets;
		<Assets as Inspect<_>>::balance(ASSET_ID, &PenpalAReceiver::get())
	});

	test.set_assertion::<AssetHubRococo>(system_para_to_para_assets_sender_assertions);
	test.set_assertion::<PenpalA>(system_para_to_para_assets_receiver_assertions);
	test.set_dispatchable::<AssetHubRococo>(system_para_to_para_limited_reserve_transfer_assets);
	test.assert();

	let sender_balance_after = test.sender.balance;
	let receiver_balance_after = test.receiver.balance;

	// Sender's balance is reduced
	assert!(sender_balance_after < sender_balance_before);
	// Receiver's balance is increased
	assert!(receiver_balance_after > receiver_balance_before);
	// Receiver's balance increased by `amount_to_send - delivery_fees - bought_execution`;
	// `delivery_fees` might be paid from transfer or JIT, also `bought_execution` is unknown but
	// should be non-zero
	assert!(receiver_balance_after < receiver_balance_before + fee_amount_to_send);

	let sender_assets_after = AssetHubRococo::execute_with(|| {
		type Assets = <AssetHubRococo as AssetHubRococoPallet>::Assets;
		<Assets as Inspect<_>>::balance(ASSET_ID, &AssetHubRococoSender::get())
	});
	let receiver_assets_after = PenpalA::execute_with(|| {
		type Assets = <PenpalA as PenpalAPallet>::Assets;
		<Assets as Inspect<_>>::balance(ASSET_ID, &PenpalAReceiver::get())
	});

	// Sender's balance is reduced by exact amount
	assert_eq!(sender_assets_before - asset_amount_to_send, sender_assets_after);
	// Receiver's balance is increased by exact amount
	assert_eq!(receiver_assets_after, receiver_assets_before + asset_amount_to_send);
}

fn penpal_create_foreign_asset_on_asset_hub(
	asset_id_on_penpal: MultiLocation,
	ah_as_seen_by_penpal: MultiLocation,
) -> MultiLocation {
	let ah_check_account = AssetHubRococo::execute_with(|| {
		<AssetHubRococo as AssetHubRococoPallet>::PolkadotXcm::check_account()
	});
	let penpal_check_account =
		PenpalA::execute_with(|| <PenpalA as PenpalAPallet>::PolkadotXcm::check_account());
	let penpal_as_seen_by_ah = AssetHubRococo::sibling_location_of(PenpalA::para_id());

	// prefund SA of Penpal on AHR with enough ROCs to pay for creating new foreign asset,
	// also prefund CheckingAccount with ED, because teleported asset itself is not sufficient
	// and CheckingAccount cannot be created otherwise
	let sov_penpal_on_ahr = AssetHubRococo::sovereign_account_id_of(penpal_as_seen_by_ah);
	println!(
		"===❤️====❤️====❤️=== on AHR fund {:?} {:?} with ED",
		penpal_as_seen_by_ah, sov_penpal_on_ahr
	);
	AssetHubRococo::fund_accounts(vec![
		(sov_penpal_on_ahr.clone().into(), ROCOCO_ED * 100_000_000_000),
		(ah_check_account.clone().into(), ROCOCO_ED * 1000),
	]);

	// prefund SA of AHR on Penpal with some ROCs
	let sov_ahr_on_penpal = PenpalA::sovereign_account_id_of(ah_as_seen_by_penpal);
	println!(
		"===❤️====❤️====❤️=== on Penpal fund {:?} {:?} with ED",
		ah_as_seen_by_penpal, sov_ahr_on_penpal
	);
	PenpalA::fund_accounts(vec![
		(sov_ahr_on_penpal.into(), ROCOCO_ED * 1_000_000_000),
		(penpal_check_account.clone().into(), ROCOCO_ED * 1000),
	]);

	// Force create asset on PenpalA and prefund PenpalASender
	PenpalA::force_create_and_mint_asset(
		TELEPORTABLE_ASSET_ID,
		ASSET_MIN_BALANCE,
		false,
		PenpalASender::get(),
		None,
		ASSET_MIN_BALANCE * 1_000_000,
	);

	let foreign_asset_at_asset_hub_rococo = MultiLocation {
		parents: 1,
		// interior: asset_id_on_penpal.interior,
		// TODO
		interior: X3(
			Parachain(PenpalA::para_id().into()),
			PalletInstance(50),
			GeneralIndex(TELEPORTABLE_ASSET_ID.into()),
		),
	};

	let require_weight_at_most = Weight::from_parts(1_100_000_000_000, 30_000);
	let origin_kind = OriginKind::Xcm;
	let sov_penpal_on_ahr_as_location = MultiLocation {
		parents: 0,
		interior: X1(AccountId32Junction { network: None, id: sov_penpal_on_ahr.clone().into() }),
	};
	let call_create_foreign_assets =
		<AssetHubRococo as Chain>::RuntimeCall::ForeignAssets(pallet_assets::Call::<
			<AssetHubRococo as Chain>::Runtime,
			pallet_assets::Instance2,
		>::create {
			id: foreign_asset_at_asset_hub_rococo,
			min_balance: ASSET_MIN_BALANCE,
			// admin: sov_penpal_on_ahr.into(),
			admin: AssetHubRococoSender::get().into(),
		})
		.encode();
	// let call_mint_foreign_assets =
	// 	<AssetHubRococo as Chain>::RuntimeCall::ForeignAssets(pallet_assets::Call::<
	// 		<AssetHubRococo as Chain>::Runtime,
	// 		pallet_assets::Instance2,
	// 	>::mint {
	// 		id: foreign_asset_at_asset_hub_rococo,
	// 		beneficiary: AssetHubRococoSender::get().into(),
	// 		amount: ASSET_MIN_BALANCE * 1_000_000, //sov_penpal_on_ahr.into(),
	// 	})
	// 	.encode();
	let buy_execution_fee_amount = parachains_common::rococo::fee::WeightToFee::weight_to_fee(
		&Weight::from_parts(10_100_000_000_000, 300_000),
	);
	let buy_execution_fee = MultiAsset {
		id: Concrete(MultiLocation { parents: 1, interior: Here }),
		fun: Fungible(buy_execution_fee_amount),
	};
	let xcm = VersionedXcm::from(Xcm(vec![
		WithdrawAsset { 0: vec![buy_execution_fee.clone()].into() },
		BuyExecution { fees: buy_execution_fee.clone(), weight_limit: Unlimited },
		Transact { require_weight_at_most, origin_kind, call: call_create_foreign_assets.into() },
		ExpectTransactStatus(MaybeErrorCode::Success),
		// Transact { require_weight_at_most, origin_kind, call: call_mint_foreign_assets.into() },
		// ExpectTransactStatus(MaybeErrorCode::Success),
		RefundSurplus,
		DepositAsset { assets: All.into(), beneficiary: sov_penpal_on_ahr_as_location },
	]));
	// Send XCM message from penpal => asset_hub_rococo
	let sudo_penpal_origin = <PenpalA as Chain>::RuntimeOrigin::root();
	PenpalA::execute_with(|| {
		assert_ok!(<PenpalA as PenpalAPallet>::PolkadotXcm::send(
			sudo_penpal_origin.clone(),
			bx!(ah_as_seen_by_penpal.into()),
			bx!(xcm),
		));

		type RuntimeEvent = <PenpalA as Chain>::RuntimeEvent;

		assert_expected_events!(
			PenpalA,
			vec![
				RuntimeEvent::PolkadotXcm(pallet_xcm::Event::Sent { .. }) => {},
			]
		);
	});

	let prefund_amount = ASSET_MIN_BALANCE * 1_000_000;
	AssetHubRococo::execute_with(|| {
		type ForeignAssets = <AssetHubRococo as AssetHubRococoPallet>::ForeignAssets;
		assert!(ForeignAssets::asset_exists(foreign_asset_at_asset_hub_rococo));

		assert_ok!(ForeignAssets::mint(
			<AssetHubRococo as Chain>::RuntimeOrigin::signed(AssetHubRococoSender::get()),
			foreign_asset_at_asset_hub_rococo,
			AssetHubRococoSender::get().into(),
			prefund_amount,
		));
		assert_eq!(
			<ForeignAssets as Inspect<_>>::balance(
				foreign_asset_at_asset_hub_rococo,
				&AssetHubRococoSender::get(),
			),
			prefund_amount
		);

		assert_ok!(ForeignAssets::mint(
			<AssetHubRococo as Chain>::RuntimeOrigin::signed(AssetHubRococoSender::get()),
			foreign_asset_at_asset_hub_rococo,
			ah_check_account.clone().into(),
			prefund_amount,
		));
		assert_eq!(
			<ForeignAssets as Inspect<_>>::balance(
				foreign_asset_at_asset_hub_rococo,
				&ah_check_account,
			),
			prefund_amount
		);

		println!("AH events: {:?}", <AssetHubRococo as Chain>::events());
	});
	PenpalA::execute_with(|| {
		type Assets = <PenpalA as PenpalAPallet>::Assets;
		assert_ok!(Assets::mint(
			<PenpalA as Chain>::RuntimeOrigin::signed(PenpalASender::get()),
			TELEPORTABLE_ASSET_ID.into(),
			penpal_check_account.clone().into(),
			prefund_amount,
		));
		assert_eq!(
			<Assets as Inspect<_>>::balance(TELEPORTABLE_ASSET_ID.into(), &penpal_check_account,),
			prefund_amount
		);
		println!("AH events: {:?}", <AssetHubRococo as Chain>::events());
	});

	foreign_asset_at_asset_hub_rococo
}

/// Bidirectional teleports of local Penpal assets to Asset Hub as foreign assets should work
#[test]
fn penpal_to_ah_bidirectional_transfers_foreign_assets_from_para_to_asset_hub() {
	let ah_as_seen_by_penpal = PenpalA::sibling_location_of(AssetHubRococo::para_id());
	let asset_id_on_penpal = LocalTeleportableToAssetHub::get();
	let foreign_asset_at_asset_hub_rococo =
		penpal_create_foreign_asset_on_asset_hub(asset_id_on_penpal, ah_as_seen_by_penpal);
	let penpal_to_ah_beneficiary_id = AssetHubRococoReceiver::get();

	let fee_amount_to_send = ASSET_HUB_ROCOCO_ED * 10_000;
	let asset_amount_to_send = ASSET_MIN_BALANCE * 1000;

	let penpal_assets: MultiAssets = vec![
		(Parent, fee_amount_to_send).into(),
		(asset_id_on_penpal, asset_amount_to_send).into(),
	]
	.into();
	let fee_asset_index = penpal_assets
		.inner()
		.iter()
		.position(|r| r == &(Parent, fee_amount_to_send).into())
		.unwrap() as u32;

	// Penpal to AH test args
	let penpal_to_ah_test_args = TestContext {
		sender: PenpalASender::get(),
		receiver: AssetHubRococoReceiver::get(),
		args: para_test_args(
			ah_as_seen_by_penpal,
			penpal_to_ah_beneficiary_id,
			asset_amount_to_send,
			penpal_assets,
			None,
			fee_asset_index,
		),
	};
	let mut penpal_to_ah = ParaToSystemParaTest::new(penpal_to_ah_test_args);

	let sender_balance_before = penpal_to_ah.sender.balance;
	let receiver_balance_before = penpal_to_ah.receiver.balance;

	let sender_assets_before = PenpalA::execute_with(|| {
		type Assets = <PenpalA as PenpalAPallet>::Assets;
		<Assets as Inspect<_>>::balance(TELEPORTABLE_ASSET_ID, &PenpalASender::get())
	});
	let receiver_assets_before = AssetHubRococo::execute_with(|| {
		type Assets = <AssetHubRococo as AssetHubRococoPallet>::ForeignAssets;
		<Assets as Inspect<_>>::balance(
			foreign_asset_at_asset_hub_rococo,
			&AssetHubRococoReceiver::get(),
		)
	});

	// penpal_to_ah.set_assertion::<PenpalA>();
	// penpal_to_ah.set_assertion::<AssetHubRococo>();
	penpal_to_ah.set_dispatchable::<PenpalA>(para_to_system_para_transfer_assets);
	penpal_to_ah.assert();

	let sender_balance_after = penpal_to_ah.sender.balance;
	let receiver_balance_after = penpal_to_ah.receiver.balance;

	// Sender's balance is reduced
	println!("sender dot before {:?} after {:?}", sender_balance_before, sender_balance_after);
	// Receiver's balance is increased
	println!(
		"receiver dot before {:?} after {:?}",
		receiver_balance_before, receiver_balance_after
	);

	// Sender's balance is reduced
	assert!(sender_balance_after < sender_balance_before);
	// Receiver's balance is increased
	assert!(receiver_balance_after > receiver_balance_before);
	// Receiver's balance increased by `amount_to_send - delivery_fees - bought_execution`;
	// `delivery_fees` might be paid from transfer or JIT, also `bought_execution` is unknown but
	// should be non-zero
	assert!(receiver_balance_after < receiver_balance_before + fee_amount_to_send);

	let sender_assets_after = PenpalA::execute_with(|| {
		type Assets = <PenpalA as PenpalAPallet>::Assets;
		<Assets as Inspect<_>>::balance(TELEPORTABLE_ASSET_ID, &PenpalASender::get())
	});
	let receiver_assets_after = AssetHubRococo::execute_with(|| {
		type Assets = <AssetHubRococo as AssetHubRococoPallet>::ForeignAssets;
		<Assets as Inspect<_>>::balance(
			foreign_asset_at_asset_hub_rococo,
			&AssetHubRococoReceiver::get(),
		)
	});

	// Sender's balance is reduced
	println!("sender asset before {:?} after {:?}", sender_assets_before, sender_assets_after);
	// Receiver's balance is increased
	println!(
		"receiver asset before {:?} after {:?}",
		receiver_assets_before, receiver_assets_after
	);

	// Sender's balance is reduced by exact amount
	assert_eq!(sender_assets_before - asset_amount_to_send, sender_assets_after);
	// Receiver's balance is increased by exact amount
	assert_eq!(receiver_assets_after, receiver_assets_before + asset_amount_to_send);

	////////////////////////////////////////////////////////////////////////////////////

	// Now test transferring foreign assets back to Penpal
}

/// Bidirectional teleports of local Penpal assets to Asset Hub as foreign assets should work
#[test]
fn ah_to_penpal_bidirectional_transfers_foreign_assets_from_para_to_asset_hub() {
	let penpal_as_seen_by_ah = AssetHubRococo::sibling_location_of(PenpalA::para_id());
	let ah_as_seen_by_penpal = PenpalA::sibling_location_of(AssetHubRococo::para_id());
	let asset_id_on_penpal = LocalTeleportableToAssetHub::get();
	let foreign_asset_at_asset_hub_rococo =
		penpal_create_foreign_asset_on_asset_hub(asset_id_on_penpal, ah_as_seen_by_penpal);

	// let fees = MultiAsset {
	// 	id: Concrete(MultiLocation { parents: 1, interior: Here }),
	// 	fun: Fungible(3333333000),
	// };
	// let fees_xcm = Some((
	// 	Xcm([TransferAsset {
	// 		assets: MultiAssets([MultiAsset {
	// 			id: Concrete(MultiLocation { parents: 1, interior: Here }),
	// 			fun: Fungible(3333333000),
	// 		}]),
	// 		beneficiary: MultiLocation { parents: 1, interior: X1(Parachain(2000)) },
	// 	}]),
	// 	Xcm([
	// 		ReserveAssetDeposited(MultiAssets([MultiAsset {
	// 			id: Concrete(MultiLocation { parents: 1, interior: Here }),
	// 			fun: Fungible(3333333000),
	// 		}])),
	// 		BuyExecution {
	// 			fees: MultiAsset {
	// 				id: Concrete(MultiLocation { parents: 1, interior: Here }),
	// 				fun: Fungible(3333333000),
	// 			},
	// 			weight_limit: Unlimited,
	// 		},
	// 	]),
	// ));

	let ah_to_penpal_beneficiary_id = PenpalAReceiver::get();

	let fee_amount_to_send = ASSET_HUB_ROCOCO_ED * 10_000;
	let asset_amount_to_send = ASSET_MIN_BALANCE * 1000;

	let ah_assets: MultiAssets = vec![
		(Parent, fee_amount_to_send).into(),
		(foreign_asset_at_asset_hub_rococo, asset_amount_to_send).into(),
	]
	.into();
	let fee_asset_index = ah_assets
		.inner()
		.iter()
		.position(|r| r == &(Parent, fee_amount_to_send).into())
		.unwrap() as u32;

	// AH to Penpal test args
	let ah_to_penpal_test_args = TestContext {
		sender: AssetHubRococoSender::get(),
		receiver: PenpalAReceiver::get(),
		args: para_test_args(
			penpal_as_seen_by_ah,
			ah_to_penpal_beneficiary_id,
			asset_amount_to_send,
			ah_assets,
			None,
			fee_asset_index,
		),
	};
	let mut ah_to_penpal = SystemParaToParaTest::new(ah_to_penpal_test_args);

	let sender_balance_before = ah_to_penpal.sender.balance;
	let receiver_balance_before = ah_to_penpal.receiver.balance;

	let sender_assets_before = AssetHubRococo::execute_with(|| {
		type ForeignAssets = <AssetHubRococo as AssetHubRococoPallet>::ForeignAssets;
		<ForeignAssets as Inspect<_>>::balance(
			foreign_asset_at_asset_hub_rococo,
			&AssetHubRococoSender::get(),
		)
	});
	let receiver_assets_before = PenpalA::execute_with(|| {
		type Assets = <PenpalA as PenpalAPallet>::Assets;
		<Assets as Inspect<_>>::balance(TELEPORTABLE_ASSET_ID, &PenpalAReceiver::get())
	});

	// penpal_to_ah.set_assertion::<???>();
	// penpal_to_ah.set_assertion::<???>();
	ah_to_penpal.set_dispatchable::<AssetHubRococo>(system_para_to_para_transfer_assets);
	ah_to_penpal.assert();

	let sender_balance_after = ah_to_penpal.sender.balance;
	let receiver_balance_after = ah_to_penpal.receiver.balance;

	// Sender's balance is reduced
	println!("sender dot before {:?} after {:?}", sender_balance_before, sender_balance_after);
	// Receiver's balance is increased
	println!(
		"receiver dot before {:?} after {:?}",
		receiver_balance_before, receiver_balance_after
	);

	// Sender's balance is reduced
	assert!(sender_balance_after < sender_balance_before);
	// Receiver's balance is increased
	assert!(receiver_balance_after > receiver_balance_before);
	// Receiver's balance increased by `amount_to_send - delivery_fees - bought_execution`;
	// `delivery_fees` might be paid from transfer or JIT, also `bought_execution` is unknown but
	// should be non-zero
	assert!(receiver_balance_after < receiver_balance_before + fee_amount_to_send);

	let sender_assets_after = AssetHubRococo::execute_with(|| {
		type ForeignAssets = <AssetHubRococo as AssetHubRococoPallet>::ForeignAssets;
		<ForeignAssets as Inspect<_>>::balance(
			foreign_asset_at_asset_hub_rococo,
			&AssetHubRococoSender::get(),
		)
	});
	let receiver_assets_after = PenpalA::execute_with(|| {
		type Assets = <PenpalA as PenpalAPallet>::Assets;
		<Assets as Inspect<_>>::balance(TELEPORTABLE_ASSET_ID, &PenpalAReceiver::get())
	});

	// Sender's balance is reduced
	println!("sender asset before {:?} after {:?}", sender_assets_before, sender_assets_after);
	// Receiver's balance is increased
	println!(
		"receiver asset before {:?} after {:?}",
		receiver_assets_before, receiver_assets_after
	);

	// Sender's balance is reduced by exact amount
	assert_eq!(sender_assets_before - asset_amount_to_send, sender_assets_after);
	// Receiver's balance is increased by exact amount
	assert_eq!(receiver_assets_after, receiver_assets_before + asset_amount_to_send);
}
