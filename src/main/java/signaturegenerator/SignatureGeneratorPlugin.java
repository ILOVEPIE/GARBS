package signaturegenerator;

import java.awt.BorderLayout;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.*;


import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.OptionDialogBuilder;
import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Mask;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import resources.Icons;

/**
 * This plugin generates binary signatures for identifying code at runtime.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.MISC,
	shortDescription = "Generates signatures in Standard, NSig FNV1a64 and NSig CRC64 (64bit WavSig) formats.",
	description = "A plugin to assist in the generation of signatures for obtaining offsets in running software."
)
//@formatter:on
public class SignatureGeneratorPlugin extends ProgramPlugin {

	SignatureGenProvider provider;
	
	SignatureGenerator signatureGen;
	
	DockingAction action;
	
	AtomicBoolean processing = new AtomicBoolean(false);
	
	static final class SignatureResults {
		int length = Integer.MAX_VALUE;
		SignatureGenerator.Signature finalSignature = null;
		int finalSignatureOffset = 0;
	}

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public SignatureGeneratorPlugin(PluginTool tool) {
		super(tool);
		
		// TODO: Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new SignatureGenProvider(this, pluginName);
		signatureGen = new SignatureGenerator();
		SignatureGeneratorPlugin plugin = this;
		OptionDialogBuilder builder = new OptionDialogBuilder("GARBS: Ghidra Artificer of Runtime Binary Signatures","Please select the signature generation mode");
		builder.setIcon(Icons.get("images/signature.png"));
		builder.addOption("Selection");
		builder.addOption("Function");
		builder.addCancel();
		action = new DockingAction("Generate Signature", this.getName()){
			@Override
			public void actionPerformed(ActionContext context) {
				int mode = builder.show(tool.getActiveWindow());
				if(mode == 0)
					return;
				if(plugin.generateSignatures(mode)&&!provider.isVisible())
					provider.setVisible(true);
			}
		};
		action.setToolBarData(new ToolBarData(Icons.get("images/signature.png"), null));
		action.setEnabled(false);
		action.markHelpUnnecessary();
		this.getTool().addAction(action);
	}

	@Override
	public void init() {
		super.init();
		// TODO: Acquire services if necessary
	}
	
	@Override
	public void selectionChanged(ProgramSelection selection) {
		super.selectionChanged(selection);
		if(selection != null && !selection.isEmpty() && !processing.get()) {
			action.setEnabled(true);
		}else{
			action.setEnabled(false);
		}
	}
	
	public boolean generateSignatures(int mode) {
		ProgramSelection selection = this.getProgramSelection();
		if(selection.getNumAddressRanges() > 1) {
			Msg.error(this, "Cannot create a signature with multiple selections.");
			return false;
		}
		if(processing.compareAndSet(true, true))
			return false;
		action.setEnabled(false);
		provider.setText("Generating and validating signatures...");
		try {
			Program prog = this.getCurrentProgram();
			Address startAddress = selection.getMinAddress();
			//Address endAddress = selection.getMaxAddress();
			
			Function parentFunction = prog.getFunctionManager().getFunctionContaining(startAddress);
			
			Address genStartAddress = parentFunction.getBody().getMinAddress();
			Address genEndAddress = parentFunction.getBody().getMaxAddress();
			
			if(mode == 2) {
				startAddress = genStartAddress;
				//endAddress = genEndAddress;
			}
			final Address startAddressFinal = startAddress;
			long genLength = genEndAddress.getOffset()-genStartAddress.getOffset();
			long selectionOffset = startAddress.getOffset()-genStartAddress.getOffset();
			SignatureGenerationHelper.MaskedData data = SignatureGenerationHelper.maskData(prog,genStartAddress,genEndAddress);
			final byte[] maskedBytesFinal = data.data;
			final byte[] maskFinal = data.mask;
			int procs = Runtime.getRuntime().availableProcessors();
			int cores = 1;
			if((procs & 1) != 0)
				cores = procs/2;
			else
				cores = procs;
			ThreadPoolExecutor pool = new ThreadPoolExecutor(cores, procs, 500, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<Runnable>(maskedBytesFinal.length));
			final SignatureResults results = new SignatureResults();
			final Object syncObject = new Object();
			final Test exitTest = new Test() {

				@Override
				public boolean check() {
					synchronized(syncObject) {
						if(results.length <= 6)
							return true;
					}
					return false;
				}
				
			};
			final Set<Long> set = new ConcurrentSkipListSet<Long>();//Collections.newSetFromMap(new ConcurrentHashMap<String,Boolean>());
			final String lineSep = System.lineSeparator();
			int jobCount = 0;
			{
				for(int offset = 0; offset < genLength; offset+=3) {
					
					
					final int forwardOffset = (int)(offset+selectionOffset);
					final int backwardOffset = (int)(selectionOffset-offset-64);
					
					final int forwardRelativeOffset = (int)(offset);
					final int backwardRelativeOffset = (int)(-offset-64);
					
					if(forwardOffset < genLength-64 && forwardOffset >= 0) {
						jobCount++;
						pool.execute(new Runnable() {

							final int aoffset = forwardOffset;
							final int roffset = forwardRelativeOffset;
							
							@Override
							public void run() {
								if(exitTest.check())
									return;
								byte[] localMaskedData = new byte[64];
								byte[] localMask = new byte[64];
								System.arraycopy(maskedBytesFinal,aoffset,localMaskedData,0,64);
								System.arraycopy(maskFinal,aoffset,localMask,0,64);
								SignatureGenerator.GeneratedResult output = SignatureGenerator.generateSignature(prog,startAddressFinal,localMaskedData,localMask,roffset,set,exitTest);
								if(output != null) {
									synchronized(syncObject) {
										int resultsMatchCount = 0;
										if(results.finalSignature != null)
											resultsMatchCount = results.finalSignature.matches;
										if(resultsMatchCount <= 0 || output.signature.length + output.signature.matches < results.length + resultsMatchCount) {
											results.finalSignature = output.signature;
											results.finalSignatureOffset = -(roffset+output.subOffset);
											results.length = output.signature.length;
											Msg.info(this,"New best candidate pattern found");
										}
									}
								}
							}
							
						});
					}
					
					if(backwardOffset < genLength-64 && backwardOffset >= 0) {
						jobCount++;
						pool.execute(new Runnable() {
							
							final int aoffset = backwardOffset;
							final int roffset = backwardRelativeOffset;
							
							@Override
							public void run() {
								if(exitTest.check())
									return;
								byte[] localMaskedData = new byte[64];
								byte[] localMask = new byte[64];
								System.arraycopy(maskedBytesFinal,aoffset,localMaskedData,0,64);
								System.arraycopy(maskFinal,aoffset,localMask,0,64);
								SignatureGenerator.GeneratedResult output = SignatureGenerator.generateSignature(prog,startAddressFinal,localMaskedData,localMask,roffset,set,exitTest);
								if(output != null) {
									synchronized(syncObject) {
										int resultsMatchCount = 0;
										if(results.finalSignature != null)
											resultsMatchCount = results.finalSignature.matches;
										if(resultsMatchCount <= 0 || output.signature.length + output.signature.matches < results.length + resultsMatchCount) {
											results.finalSignature = output.signature;
											results.finalSignatureOffset = -(roffset+output.subOffset);
											results.length = output.signature.length;
											Msg.info(this,"New best candidate pattern found");
										}
									}
								}
							}
						});
					}
				}
			}
			{
				final int jobCountFinal = jobCount;
				pool.execute(new Runnable() {
	
					@Override
					public void run() {
						long completeCount = pool.getCompletedTaskCount();
						while( completeCount < jobCountFinal) {
							try{Thread.sleep(25);}catch(Exception e) {}
							completeCount = pool.getCompletedTaskCount();
						}
						synchronized(syncObject) {
							SignatureGenerator.Signature finalSignature = results.finalSignature;
							int finalSignatureOffset = results.finalSignatureOffset;
							if(finalSignature == null) {
								processing.set(false);
								pool.shutdown();
								provider.setText("No Signatures found.");
								return;
							}
							
							long fnv_signature = Hasher.fnv1a64(finalSignature.data);
							long crc_signature = Hasher.crc64(finalSignature.data);
							long mask = 0;
							String string_mask = "";
							for(int i = 0; i < finalSignature.mask.length; i++) {
								if(finalSignature.mask[i] == -1) {
									mask |= (1L << i);
									string_mask += "x";
								} else {
									string_mask += "?";
								}
							}
							String signature = "";
							for(int i = 0; i < finalSignature.data.length; i++) {
								signature += "\\x"+String.format("%02X",finalSignature.data[i]).toUpperCase(); 
							}
							
							String lineSep = System.lineSeparator();
							provider.setText("fnv1a: 0x"+Long.toHexString(fnv_signature).toUpperCase()+" 0x"+Long.toHexString(mask).toUpperCase()+
											lineSep+"crc: 0x"+Long.toHexString(crc_signature).toUpperCase()+" 0x"+Long.toHexString(mask).toUpperCase()+
											lineSep+"normal: "+signature+" "+string_mask+lineSep+"offset: "+finalSignatureOffset);
							processing.set(false);
							pool.shutdown();
						}
					}
					
				});
			}
		}catch(Exception e) {
			processing.set(false);
			action.setEnabled(true);
			Msg.error(this,e);
			return false;
		}
		return true;
	}

	// TODO: If provider is desired, it is recommended to move it to its own file
	private static class SignatureGenProvider extends ComponentProvider {

		JTextArea textArea;
		private JPanel resultPanel;
		private final String defaultText = "Generating signatures...";

		public SignatureGenProvider(SignatureGeneratorPlugin plugin, String owner) {
			super(plugin.getTool(), "Ghidra Artificer of Runtime Binary Signatures", owner);
			buildPanel();
		}
	
		public void setText(String text) {
			textArea.setRows(3);
			textArea.setColumns(329);
			textArea.setText(text);
		}
		// Customize GUI
		private void buildPanel() {
			resultPanel = new JPanel(new BorderLayout());
			textArea = new JTextArea(defaultText, 3, 266);
			textArea.setEditable(false);
			resultPanel.add(new JScrollPane(textArea));
		}

		@Override
		public JComponent getComponent() {
			return resultPanel;
		}
	}
}
